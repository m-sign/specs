# m-sign Data Formats

| | |
|---|---|
| **Version** | 1.0.0 |
| **Status** | Stable |
| **Date** | 2026-10-21 |
| **Format version** | `0x01` (v1) |
| **Test vectors** | [`test-vectors/v1.json`](test-vectors/v1.json) |

This document specifies the text formats m-sign uses to store and exchange Ed25519 private keys, public keys and detached signatures.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as shown here.

Notation:

- `A || B` is the concatenation of byte strings `A` and `B`.
- `X[i:j]` is the bytes of `X` from offset `i` (inclusive) to offset `j` (exclusive). Offsets are zero-based.
- `SHA-256(X)` and `SHA-512(X)` are the hash functions defined in [FIPS 180-4].
- Byte values are written in lowercase hexadecimal, for example `0x01`.

Normative references:

- [RFC 8032]: Edwards-Curve Digital Signature Algorithm (EdDSA), for Ed25519.
- [RFC 4648] section 5: Base 64 encoding with URL and filename safe alphabet ("base64url").
- [FIPS 180-4]: Secure Hash Standard (SHA-256, SHA-512).
- [RFC 5234] and [RFC 7405]: ABNF and its case-sensitive string extension.

## 2. Item types

An **item** is one key or signature in text form. Each item type has a fixed prefix:

| Prefix | Item | Section |
|---|---|---|
| `KEY:` | Private key | [5](#5-private-key-v1) |
| `PUB:` | Public key | [6](#6-public-key-v1) |
| `SIG:` | Signature | [7](#7-signature-v1) |

Prefixes are case-sensitive ASCII. Each item occupies exactly one line.

## 3. Text encoding

### 3.1 Grammar

```abnf
item     = prefix data eol
prefix   = %s"KEY:" / %s"PUB:" / %s"SIG:"
data     = 1*b64char          ; exact length is fixed per item type and version
b64char  = ALPHA / DIGIT / "-" / "_"
eol      = LF / CRLF          ; readers also accept end of input in place of eol
```

`data` is the base64url encoding ([RFC 4648] section 5) of the item's binary **payload**, without padding.

### 3.2 Writers

Writers MUST:

1. emit the prefix, followed by the canonical base64url encoding of the payload without padding, followed by exactly one LF (`0x0a`);
2. set unused bits of the last base64 character to zero (canonical encoding, [RFC 4648] section 3.5);
3. emit nothing else on the line (no leading or trailing whitespace, no byte order mark).

### 3.3 Readers

Readers MUST reject an item that:

1. does not start with the expected prefix, including when a byte order mark or whitespace precedes it;
2. contains `=` padding;
3. contains any byte outside the `b64char` alphabet in `data`, including a space or CR;
4. has non-zero unused bits in the last base64 character (non-canonical encoding);
5. decodes to a payload whose length is not exactly the length defined for its item type and version;
6. fails any validation rule of its item type.

Readers MUST accept LF and CRLF as the line terminator, and SHOULD accept end of input in place of a terminator.

A reader that parses an item from a stream SHOULD NOT consume input beyond the terminator, so that several items can be read from one stream. Readers SHOULD bound how much input they read for one item. A v1 line is at most 108 bytes, so a limit of 1024 bytes is RECOMMENDED.

## 4. Common v1 fields

Every v1 payload starts with a version byte. The fields below are shared by the v1 item types.

| Field | Size | Definition | Purpose |
|---|---|---|---|
| Version | 1 | `0x01` | Selects the payload layout. It is not covered by Check. |
| KeyID | 6 | `SHA-256(PublicKey)[0:6]` | Lets a verifier pick the right public key. It is a hint, not proof of identity (see [10.1](#101-keyid-is-not-an-authenticator)). |
| Check | 6 | `SHA-256(payload[7:])[0:6]`, the hash of every payload byte after the Check field | Detects accidental corruption. It is not a MAC and gives no protection against deliberate modification. |

The `PublicKey` used for the KeyID is the 32-byte Ed25519 public key ([RFC 8032] section 5.1.5).

## 5. Private key (v1)

### 5.1 Layout

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Version = `0x01` |
| 1 | 6 | Check = `SHA-256(payload[7:77])[0:6]` |
| 7 | 6 | KeyID = `SHA-256(PublicKey)[0:6]` |
| 13 | 32 | Seed: the 32-byte Ed25519 private key of [RFC 8032] section 5.1.5 |
| 45 | 32 | PublicKey: the Ed25519 public key derived from Seed |

The payload is 77 bytes. It encodes to 103 base64 characters, so the full line, including `KEY:` and LF, is 108 bytes.

Bytes 13 to 76 (Seed || PublicKey) are the 64-byte private key representation used by Go's `crypto/ed25519` and by libsodium.

### 5.2 Generation

The Seed MUST be 32 bytes from a cryptographically secure random number generator. PublicKey, KeyID and Check are then computed as defined above.

### 5.3 Validation on import

Readers MUST apply these checks, in this order, and reject the item if any of them fails:

1. The text rules of [section 3.3](#33-readers) (prefix, alphabet, padding, canonical encoding).
2. The payload is at least 1 byte long.
3. Version is `0x01`. Any other value MUST be reported as an *unsupported version* error ([section 8](#8-versioning-and-extensibility)).
4. The payload is exactly 77 bytes long.
5. Check equals `SHA-256(payload[7:77])[0:6]`.
6. KeyID equals `SHA-256(PublicKey)[0:6]`.
7. PublicKey equals the public key derived from Seed.

Checks 6 and 7 matter for security. A private key whose PublicKey field does not match its Seed must never be used for signing: if the same message is signed under two different PublicKey values, the two signatures reveal the secret scalar.

Comparisons that involve secret data (checks 5 and 7) SHOULD be constant-time.

## 6. Public key (v1)

### 6.1 Layout

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Version = `0x01` |
| 1 | 6 | KeyID = `SHA-256(PublicKey)[0:6]` |
| 7 | 32 | PublicKey |

The payload is 39 bytes. It encodes to 52 base64 characters, so the full line, including `PUB:` and LF, is 57 bytes.

A public key has no Check field; the KeyID plays that role.

### 6.2 Validation on import

Readers MUST apply these checks, in this order:

1. The text rules of [section 3.3](#33-readers).
2. The payload is at least 1 byte long.
3. Version is `0x01`. Any other value is an *unsupported version* error.
4. The payload is exactly 39 bytes long.
5. KeyID equals `SHA-256(PublicKey)[0:6]`.

Readers MAY additionally reject a PublicKey that is not a canonical encoding of a point on the curve, or that is a small-order point. Such keys can never validate a signature (see [7.4](#74-verification)), so this only moves the failure earlier.

## 7. Signature (v1)

### 7.1 Layout

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Version = `0x01` |
| 1 | 6 | Check = `SHA-256(payload[7:77])[0:6]` |
| 7 | 6 | KeyID of the signing key |
| 13 | 64 | Signature: the Ed25519 signature `R || S` |

The payload is 77 bytes. It encodes to 103 base64 characters, so the full line, including `SIG:` and LF, is 108 bytes.

A signature is detached: the signed message is not part of the item.

### 7.2 Signing

To sign a message `M` (any byte sequence):

1. Compute `M' = SHA-512(M)` (64 bytes).
2. Compute `Signature = Ed25519-Sign(Seed, M')` as specified in [RFC 8032] section 5.1.6, with `M'` as the message.
3. Build the payload with the signer's KeyID and compute Check.

Step 2 is **PureEdDSA** Ed25519 applied to the 64-byte digest. It is **not** Ed25519ph and **not** Ed25519ctx ([RFC 8032] section 5.1): there is no `dom2` prefix and no context string. For interoperability, the result is the same as libsodium's `crypto_sign_detached(sig, NULL, SHA-512(M), 64, sk)` or Go's `d := sha512.Sum512(M); ed25519.Sign(priv, d[:])`.

Ed25519 signing is deterministic. Signing the same message with the same key always produces the same item.

### 7.3 Validation on import

Readers MUST apply these checks, in this order:

1. The text rules of [section 3.3](#33-readers).
2. The payload is at least 1 byte long.
3. Version is `0x01`. Any other value is an *unsupported version* error.
4. The payload is exactly 77 bytes long.
5. Check equals `SHA-256(payload[7:77])[0:6]`.

Import does not verify the signature cryptographically, because the message is not part of the item.

### 7.4 Verification

To verify a signature item against a message `M` and a public key item, a verifier MUST:

1. Compare the signature's KeyID with the public key's KeyID. If they differ, the signature is invalid (*key ID mismatch*). The verifier MUST NOT try other keys based on the KeyID alone; key selection is the caller's decision.
2. Compute `M' = SHA-512(M)` and verify `Signature` over `M'` with PublicKey as specified in [RFC 8032] section 5.1.7. Verifiers MUST reject a signature whose `S` is not less than the group order `L`.

The signature is valid only if both steps succeed.

Note: Ed25519 libraries differ on some edge cases that honest signers never produce (for example, signatures built from small-order points). The reference implementation (Go `crypto/ed25519`) uses the cofactorless verification equation. Applications that need every implementation to reach identical verdicts on adversarial inputs should pin the verifier.

## 8. Versioning and extensibility

The version byte selects the payload layout:

| Value | Meaning |
|---|---|
| `0x01` | The v1 layouts in this document |
| `0x00`, `0x02`–`0xff` | Reserved |

Readers MUST reject a payload with an unknown version and SHOULD report it as an *unsupported version* error, distinct from a malformed item, so that users can tell an old reader from a corrupted file.

New kinds of items get new prefixes. Existing prefixes and the v1 layouts will never change meaning.

This document uses semantic versioning:

- **MAJOR**: a new, incompatible format version (a new version byte value).
- **MINOR**: new item types or optional features that existing v1 readers can ignore.
- **PATCH**: editorial changes that do not change any requirement.

## 9. Conventions (informative)

These conventions are used by the m-sign tools. They are not part of the format.

- A signature for a file `F` is stored in `F.msign`, which holds one `SIG:` item.
- The environment variables `MSIGN_PRIVATE` and `MSIGN_PUBLIC` each hold one `KEY:` or `PUB:` item. The line terminator is optional there.
- Recommended file permissions: `0600` for private keys; `0644` for public keys and signatures.

## 10. Security considerations

### 10.1 KeyID is not an authenticator

The KeyID is only 48 bits. Finding two keys with the same KeyID takes about 2^24 work, and finding a key that matches a given KeyID takes about 2^48. A KeyID therefore only helps pick a candidate key. Trust MUST be anchored on the complete public key, obtained through a trusted channel.

### 10.2 Check is not a MAC

Anyone can recompute Check after modifying an item. It detects accidental corruption, such as a truncated copy, and nothing more.

### 10.3 Private keys are stored in plaintext

A `KEY:` item contains the secret Seed without encryption. Store it with restrictive file permissions or in a secret manager, never commit it to version control, and avoid printing it to logs or terminals. This version of the format has no encrypted key item.

### 10.4 Randomness

Key generation needs a cryptographically secure random number generator. Signing is deterministic and needs no randomness.

### 10.5 What a signature binds

A signature covers only the bytes of the message. It does not bind the file name, a version number, a timestamp or the purpose of the signature. A valid signature for one file is also valid for any copy of it under another name, and an old signed file stays valid forever. Applications that need such bindings should sign a manifest that contains them, for example a list of file names and SHA-256 hashes that includes the release version.

### 10.6 Pre-hashing

Because the message is hashed with SHA-512 before signing, the security of a signature depends on the collision resistance of SHA-512, unlike PureEdDSA over the full message. SHA-512 is considered collision-resistant.

### 10.7 Key reuse

There is no domain separation between m-sign signatures and other uses of Ed25519. Do not use an m-sign key in any other protocol.

### 10.8 Implementation

Implementations should use a constant-time Ed25519 implementation, and should not include secret bytes in error messages.

## 11. Test vectors

[`test-vectors/v1.json`](test-vectors/v1.json) contains:

| Section | Content |
|---|---|
| `keys` | Three test keys with their seed, public key, KeyID, `KEY:` and `PUB:` items |
| `signatures` | Signatures by every test key over four messages: empty, `abc`, 1000 × `a`, and 1024 bytes where byte *i* is *i* mod 251 |
| `invalid` | Items that readers MUST reject, with the expected error class: `format` or `unsupported_version` |
| `verify_invalid` | Signature/message/key combinations that MUST fail verification: `invalid_signature` or `key_id_mismatch` |
| `accepted_variants` | Inputs readers MUST accept (CRLF terminator) or SHOULD accept (no terminator), with the canonical form they re-encode to |

All keys in the vectors are published test keys. Never use them for real signing.

The vectors are generated and checked by [`tools/vectors.py`](tools/vectors.py), an independent implementation that uses only the Python standard library.

### 11.1 Worked example (`kat-a`)

```
Seed       3f1f6bd5178138c2aec10f06623e7dd99dcc9a85386ebabb626defed96f6ff02
PublicKey  068568b499dcf7a1a55f09971284d35c45762975b527ecb02f77ba5ddf6f315f
KeyID      386e418a77ca                       (SHA-256(PublicKey)[0:6])
```

Private key:

```
KEY:Aef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8

Version    01
Check      e7fc2a20fc6d
KeyID      386e418a77ca
Seed       3f1f6bd5178138c2aec10f06623e7dd99dcc9a85386ebabb626defed96f6ff02
PublicKey  068568b499dcf7a1a55f09971284d35c45762975b527ecb02f77ba5ddf6f315f
```

Public key:

```
PUB:AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf

Version    01
KeyID      386e418a77ca
PublicKey  068568b499dcf7a1a55f09971284d35c45762975b527ecb02f77ba5ddf6f315f
```

Signature over the empty message (`M' = SHA-512("") = cf83e135…927da3e`):

```
SIG:AfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk

Version    01
Check      f5fe25a184d9
KeyID      386e418a77ca
R          3e65843eb6f2520d59784ecb4156dc41f87c5c5eef9fef3b98a484c635249767
S          0e2389a14720ed1e7ec83d5c4736bc8d1de0f80e9d0758cd5154d04b06a8a509
```

## 12. Document history

| Version | Date | Changes |
|---|---|---|
| 1.0.0 | 2026-10-21 | First normative version. Adds BCP 14 keywords, exact lengths, byte layouts, text-encoding rules, private-key validation, the precise signing algorithm (PureEdDSA over SHA-512), versioning rules, security considerations and test vectors. Defines Check as the hash of all payload bytes after the Check field. The v1 byte format is unchanged. |

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648
[RFC 5234]: https://www.rfc-editor.org/rfc/rfc5234
[RFC 7405]: https://www.rfc-editor.org/rfc/rfc7405
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[FIPS 180-4]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
