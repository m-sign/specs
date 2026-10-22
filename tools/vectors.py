#!/usr/bin/env python3
"""Generate and verify the m-sign v1 test vectors (test-vectors/v1.json).

This script is an independent reference implementation of the m-sign v1
data formats. It uses only the Python standard library, including a port of
the RFC 8032 section 6 reference Ed25519 code, so it shares no code with the
Go implementation in github.com/m-sign/msign.

Usage:
    python3 tools/vectors.py generate   # (re)write test-vectors/v1.json
    python3 tools/vectors.py verify     # check every vector against this implementation

The reference Ed25519 code below is NOT constant-time and must not be used
with real keys. All keys in the vectors are published test keys.
"""

import base64
import hashlib
import json
import os
import sys

VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test-vectors", "v1.json")
SPEC_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Ed25519, RFC 8032 section 6 reference implementation (not constant-time).
# ---------------------------------------------------------------------------

P = 2**255 - 19
D = -121665 * pow(121666, P - 2, P) % P
L = 2**252 + 27742317777372353535851937790883648493  # group order
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _point_add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    d = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f, g * h, f * g, e * h)


def _point_mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, pt)
        pt = _point_add(pt, pt)
        s >>= 1
    return q


def _point_equal(p1, p2):
    if (p1[0] * p2[2] - p2[0] * p1[2]) % P != 0:
        return False
    return (p1[1] * p2[2] - p2[1] * p1[2]) % P == 0


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def _compress(pt):
    zinv = pow(pt[2], P - 2, P)
    x = pt[0] * zinv % P
    y = pt[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _expand(seed):
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public(seed):
    return _compress(_point_mul(_expand(seed)[0], G))


def ed25519_sign(seed, msg):
    a, prefix = _expand(seed)
    pub = _compress(_point_mul(a, G))
    r = int.from_bytes(_sha512(prefix + msg), "little") % L
    rs = _compress(_point_mul(r, G))
    h = int.from_bytes(_sha512(rs + pub + msg), "little") % L
    s = (r + h * a) % L
    return rs + int.to_bytes(s, 32, "little")


def ed25519_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = _decompress(pub)
    r = _decompress(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(_sha512(sig[:32] + pub + msg), "little") % L
    return _point_equal(_point_mul(s, G), _point_add(r, _point_mul(h, a)))


# ---------------------------------------------------------------------------
# m-sign v1 encoding (writer side).
# ---------------------------------------------------------------------------

VERSION_ONE = 0x01
PREFIX = {"key": "KEY:", "pub": "PUB:", "sig": "SIG:"}
LENGTH = {"key": 77, "pub": 39, "sig": 77}
ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def sha256_6(b):
    return hashlib.sha256(b).digest()[:6]


def b64(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def key_id(pub):
    return sha256_6(pub)


def key_payload(seed, pub=None, kid=None):
    pub = ed25519_public(seed) if pub is None else pub
    kid = key_id(pub) if kid is None else kid
    body = kid + seed + pub
    return bytes([VERSION_ONE]) + sha256_6(body) + body


def pub_payload(pub, kid=None):
    kid = key_id(pub) if kid is None else kid
    return bytes([VERSION_ONE]) + kid + pub


def sig_payload(kid, sig):
    body = kid + sig
    return bytes([VERSION_ONE]) + sha256_6(body) + body


def with_check(payload):
    """Recompute the Check field (bytes 1..6) of a KEY or SIG payload."""
    return payload[:1] + sha256_6(payload[7:]) + payload[7:]


def item(typ, payload):
    return PREFIX[typ] + b64(payload) + "\n"


def sign_item(seed, msg):
    return item("sig", sig_payload(key_id(ed25519_public(seed)), ed25519_sign(seed, hashlib.sha512(msg).digest())))


# ---------------------------------------------------------------------------
# m-sign v1 parsing (reader side), following the rules in format.md.
# ---------------------------------------------------------------------------


class FormatError(Exception):
    """Raised with the error class name used in the vectors."""


def parse(text, typ):
    """Parse one item of the given type; return its decoded fields."""
    if text.endswith("\r\n"):
        line = text[:-2]
    elif text.endswith("\n"):
        line = text[:-1]
    else:
        line = text  # end of input in place of a terminator
    if "\n" in line:
        raise FormatError("format")
    if not line.startswith(PREFIX[typ]):
        raise FormatError("format")
    data = line[len(PREFIX[typ]):]
    if not data or any(c not in ALPHABET for c in data) or len(data) % 4 == 1:
        raise FormatError("format")
    payload = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    if b64(payload) != data:  # non-canonical unused bits
        raise FormatError("format")
    if payload[0] != VERSION_ONE:
        raise FormatError("unsupported_version")
    if len(payload) != LENGTH[typ]:
        raise FormatError("format")
    if typ == "key":
        check, kid, seed, pub = payload[1:7], payload[7:13], payload[13:45], payload[45:77]
        if sha256_6(payload[7:]) != check or key_id(pub) != kid or ed25519_public(seed) != pub:
            raise FormatError("format")
        return {"key_id": kid, "seed": seed, "pub": pub}
    if typ == "pub":
        kid, pub = payload[1:7], payload[7:39]
        if key_id(pub) != kid:
            raise FormatError("format")
        return {"key_id": kid, "pub": pub}
    check, kid, sig = payload[1:7], payload[7:13], payload[13:77]
    if sha256_6(payload[7:]) != check:
        raise FormatError("format")
    return {"key_id": kid, "sig": sig}


def verify_message(pub_text, msg, sig_text):
    """Return None if valid, else the error class name."""
    pub = parse(pub_text, "pub")
    sig = parse(sig_text, "sig")
    if pub["key_id"] != sig["key_id"]:
        return "key_id_mismatch"
    if not ed25519_verify(pub["pub"], hashlib.sha512(msg).digest(), sig["sig"]):
        return "invalid_signature"
    return None


def canonical(typ, fields):
    if typ == "key":
        return item("key", key_payload(fields["seed"], fields["pub"], fields["key_id"]))
    if typ == "pub":
        return item("pub", pub_payload(fields["pub"], fields["key_id"]))
    return item("sig", sig_payload(fields["key_id"], fields["sig"]))


# ---------------------------------------------------------------------------
# Vector generation.
# ---------------------------------------------------------------------------

SEEDS = [
    ("kat-a", "3f1f6bd5178138c2aec10f06623e7dd99dcc9a85386ebabb626defed96f6ff02"),
    ("kat-b", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),  # RFC 8032 7.1 TEST 1
    ("kat-c", bytes(range(32)).hex()),
]

MESSAGES = [
    ("empty", b""),
    ("abc", b"abc"),
    ("a1000", b"a" * 1000),
    ("pattern1024", bytes(i % 251 for i in range(1024))),
]


def _decode(text):
    data = text.rstrip("\n")[4:]
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _flip_last_char(text):
    """Return text whose last base64 char differs only in the unused bits."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    body = text.rstrip("\n")
    idx = alphabet.index(body[-1])
    return body[:-1] + alphabet[idx ^ 1] + "\n"


def _invalid_cases(key_a, pub_a, sig_a, pub_b):
    cases = []

    def add(name, typ, text, error, comment):
        cases.append({"name": name, "type": typ, "input": text, "error": error, "comment": comment})

    valid = {"key": key_a, "pub": pub_a, "sig": sig_a}
    other = {"key": "PUB:", "pub": "SIG:", "sig": "KEY:"}
    for typ in ("key", "pub", "sig"):
        text = valid[typ]
        data = text[4:-1]
        prefix = PREFIX[typ]
        add(f"{typ}-empty", typ, "", "format", "empty input")
        add(f"{typ}-prefix-only", typ, prefix + "\n", "format", "no data after the prefix")
        add(f"{typ}-wrong-prefix", typ, other[typ] + data + "\n", "format", "prefix of another item type")
        add(f"{typ}-lowercase-prefix", typ, prefix.lower() + data + "\n", "format", "prefixes are case-sensitive")
        add(f"{typ}-missing-colon", typ, prefix[:3] + data + "\n", "format", "prefix without the colon")
        add(f"{typ}-leading-space", typ, " " + text, "format", "whitespace before the prefix")
        add(f"{typ}-leading-bom", typ, "﻿" + text, "format", "UTF-8 byte order mark before the prefix")
        add(f"{typ}-padding", typ, prefix + data + "=\n", "format", "base64 padding is not allowed")
        add(f"{typ}-plus-char", typ, prefix + "+" + data[1:] + "\n", "format", "standard base64 '+' instead of '-'")
        add(f"{typ}-slash-char", typ, prefix + "/" + data[1:] + "\n", "format", "standard base64 '/' instead of '_'")
        add(f"{typ}-space-inside", typ, prefix + data[:10] + " " + data[10:] + "\n", "format", "space inside the data")
        add(f"{typ}-cr-inside", typ, prefix + data[:10] + "\r" + data[10:] + "\n", "format", "CR inside the data")

        payload = _decode(text)
        for version in (0x00, 0x02):
            bad = bytes([version]) + payload[1:]
            add(f"{typ}-version-{version:02x}", typ, item(typ, bad), "unsupported_version",
                f"version byte 0x{version:02x} (the version byte is not covered by Check)")
        short = payload[:-1]
        long = payload + b"\x00"
        if typ != "pub":
            short, long = with_check(short), with_check(long)
        add(f"{typ}-truncated", typ, item(typ, short), "format", "payload one byte short" + ("" if typ == "pub" else " (Check recomputed)"))
        add(f"{typ}-extended", typ, item(typ, long), "format", "payload one byte long" + ("" if typ == "pub" else " (Check recomputed)"))

    add("key-noncanonical-last-char", "key", _flip_last_char(key_a), "format", "unused bits of the last char are not zero")
    add("sig-noncanonical-last-char", "sig", _flip_last_char(sig_a), "format", "unused bits of the last char are not zero")

    key_raw = _decode(key_a)
    sig_raw = _decode(sig_a)
    pub_raw = _decode(pub_a)
    add("key-bad-check", "key", item("key", key_raw[:1] + bytes([key_raw[1] ^ 1]) + key_raw[2:]), "format", "one bit of Check flipped")
    add("sig-bad-check", "sig", item("sig", sig_raw[:1] + bytes([sig_raw[1] ^ 1]) + sig_raw[2:]), "format", "one bit of Check flipped")
    add("pub-key-id-mismatch", "pub", item("pub", pub_raw[:1] + bytes([pub_raw[1] ^ 1]) + pub_raw[2:]), "format",
        "one bit of KeyID flipped")
    bad_kid = key_raw[:7] + bytes([key_raw[7] ^ 1]) + key_raw[8:]
    add("key-key-id-mismatch", "key", item("key", with_check(bad_kid)), "format",
        "KeyID is not SHA-256(PublicKey)[0:6] (Check recomputed)")
    seed = key_raw[13:45]
    other_pub = _decode(pub_b)[7:39]
    bad_pub = key_payload(seed, other_pub, key_id(other_pub))
    add("key-public-half-mismatch", "key", item("key", bad_pub), "format",
        "PublicKey is not derived from Seed (KeyID and Check recomputed)")
    return cases


def _verify_invalid_cases(pub_a, sig_a_empty, sig_b_empty):
    cases = []
    cases.append({"name": "kat-a-wrong-message", "pub": pub_a, "message_hex": b"abc".hex(), "sig": sig_a_empty,
                  "error": "invalid_signature", "comment": "signature over the empty message checked against 'abc'"})
    cases.append({"name": "kat-a-key-id-mismatch", "pub": pub_a, "message_hex": "", "sig": sig_b_empty,
                  "error": "key_id_mismatch", "comment": "kat-b signature checked with the kat-a public key"})
    raw = _decode(sig_a_empty)
    kid, sig = raw[7:13], raw[13:77]
    flipped = bytes([sig[0] ^ 1]) + sig[1:]
    cases.append({"name": "kat-a-flipped-r", "pub": pub_a, "message_hex": "", "sig": item("sig", sig_payload(kid, flipped)),
                  "error": "invalid_signature", "comment": "one bit of R flipped (Check recomputed)"})
    s = int.from_bytes(sig[32:], "little") + L
    noncanon = sig[:32] + int.to_bytes(s, 32, "little")
    cases.append({"name": "kat-a-noncanonical-s", "pub": pub_a, "message_hex": "", "sig": item("sig", sig_payload(kid, noncanon)),
                  "error": "invalid_signature", "comment": "S replaced by S + L; verifiers must reject S >= L (Check recomputed)"})
    return cases


def generate():
    keys, signatures = [], []
    for name, seed_hex in SEEDS:
        seed = bytes.fromhex(seed_hex)
        pub = ed25519_public(seed)
        keys.append({
            "name": name,
            "seed_hex": seed_hex,
            "public_key_hex": pub.hex(),
            "key_id_hex": key_id(pub).hex(),
            "key": item("key", key_payload(seed)),
            "pub": item("pub", pub_payload(pub)),
        })
        for msg_name, msg in MESSAGES:
            signatures.append({
                "name": f"{name}-{msg_name}",
                "key": name,
                "message_hex": msg.hex(),
                "sig": sign_item(seed, msg),
            })
    by_name = {k["name"]: k for k in keys}
    sig_by_name = {s["name"]: s["sig"] for s in signatures}
    key_a, pub_a, pub_b = by_name["kat-a"]["key"], by_name["kat-a"]["pub"], by_name["kat-b"]["pub"]
    sig_a = sig_by_name["kat-a-empty"]

    variants = []
    for typ, text in (("key", key_a), ("pub", pub_a), ("sig", sig_a)):
        variants.append({"name": f"{typ}-crlf", "type": typ, "input": text[:-1] + "\r\n", "canonical": text})
        variants.append({"name": f"{typ}-no-eol", "type": typ, "input": text[:-1], "canonical": text})

    return {
        "description": "m-sign v1 data format test vectors. All keys are published test keys: never use them for real signing.",
        "format_version": VERSION_ONE,
        "spec_version": SPEC_VERSION,
        "keys": keys,
        "signatures": signatures,
        "invalid": _invalid_cases(key_a, pub_a, sig_a, pub_b),
        "verify_invalid": _verify_invalid_cases(pub_a, sig_a, sig_by_name["kat-b-empty"]),
        "accepted_variants": variants,
    }


def dump(vectors):
    return json.dumps(vectors, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# Vector verification.
# ---------------------------------------------------------------------------


def verify(vectors):
    failures = []

    def fail(msg):
        failures.append(msg)

    if vectors.get("format_version") != VERSION_ONE:
        fail("format_version is not 1")

    keys = {}
    for k in vectors["keys"]:
        name = k["name"]
        seed = bytes.fromhex(k["seed_hex"])
        pub = ed25519_public(seed)
        keys[name] = seed
        if pub.hex() != k["public_key_hex"]:
            fail(f"{name}: public_key_hex is not derived from seed_hex")
        if key_id(pub).hex() != k["key_id_hex"]:
            fail(f"{name}: key_id_hex mismatch")
        try:
            fk = parse(k["key"], "key")
            fp = parse(k["pub"], "pub")
        except FormatError as e:
            fail(f"{name}: valid item rejected ({e})")
            continue
        if fk["seed"] != seed or fk["pub"] != pub or fp["pub"] != pub:
            fail(f"{name}: KEY/PUB fields do not match seed")
        if canonical("key", fk) != k["key"] or canonical("pub", fp) != k["pub"]:
            fail(f"{name}: KEY/PUB not canonical")

    pubs = {k["name"]: k["pub"] for k in vectors["keys"]}
    for s in vectors["signatures"]:
        name = s["name"]
        msg = bytes.fromhex(s["message_hex"])
        if sign_item(keys[s["key"]], msg) != s["sig"]:
            fail(f"{name}: signature is not the deterministic Ed25519 signature of SHA-512(message)")
        try:
            err = verify_message(pubs[s["key"]], msg, s["sig"])
        except FormatError as e:
            err = str(e)
        if err is not None:
            fail(f"{name}: valid signature rejected ({err})")

    for c in vectors["invalid"]:
        try:
            parse(c["input"], c["type"])
            fail(f"{c['name']}: invalid input accepted")
        except FormatError as e:
            if str(e) != c["error"]:
                fail(f"{c['name']}: expected {c['error']}, got {e}")

    for c in vectors["verify_invalid"]:
        try:
            err = verify_message(c["pub"], bytes.fromhex(c["message_hex"]), c["sig"])
        except FormatError as e:
            err = f"format ({e})"
        if err != c["error"]:
            fail(f"{c['name']}: expected {c['error']}, got {err}")

    for c in vectors["accepted_variants"]:
        try:
            got = canonical(c["type"], parse(c["input"], c["type"]))
        except FormatError as e:
            fail(f"{c['name']}: rejected ({e})")
            continue
        if got != c["canonical"]:
            fail(f"{c['name']}: re-export is not canonical")

    return failures


def main(argv):
    if len(argv) != 2 or argv[1] not in ("generate", "verify"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    if argv[1] == "generate":
        with open(VECTORS_PATH, "w", encoding="ascii", newline="\n") as f:
            f.write(dump(generate()))
        print(f"wrote {os.path.normpath(VECTORS_PATH)}")
        return 0
    with open(VECTORS_PATH, encoding="ascii") as f:
        vectors = json.load(f)
    failures = verify(vectors)
    for msg in failures:
        print("FAIL:", msg, file=sys.stderr)
    total = sum(len(vectors[k]) for k in ("keys", "signatures", "invalid", "verify_invalid", "accepted_variants"))
    if failures:
        print(f"{len(failures)} failure(s) in {total} vectors", file=sys.stderr)
        return 1
    print(f"ok: {total} vectors verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
