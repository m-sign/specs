# Data Formats

## General Format

Each exported item is an ASCII string with a fixed prefix and a trailing newline:

- Prefix: four characters identifying the type (`"KEY:"`, `"PUB:"`, `"SIG:"`).
- Data: Base64 (Raw URL, no padding) encoding of the binary payload.
- Terminator: a single `\n` newline.

Version 1 (v1) payloads use these common definitions:

- Version: 1 byte, value `0x01`.
- KeyID: 6 bytes, the first 6 bytes of `SHA256(<PublicKey>)`.
- Check: 6 bytes, the first 6 bytes of `SHA256(KeyID || payload)`, where `payload` is the field(s) that follow `Check` in that message type.

### Private Key (v1)

```
Prefix:  "KEY:"
Version: 1 byte (0x01)
Layout:  <Version> || <Check> || <KeyID> || <PrivateKey>
Where:
  - PrivateKey: Ed25519 private key bytes (64 bytes)
  - KeyID: first 6 bytes of SHA256(<PublicKey>)
  - Check: first 6 bytes of SHA256(<KeyID> || <PrivateKey>)
Data:    Base64_RawURL( <Version> || <Check> || <KeyID> || <PrivateKey> )
String:  "KEY:" + <Data> + "\n"
```

### Public Key (v1)

```
Prefix:  "PUB:"
Version: 1 byte (0x01)
Layout:  <Version> || <KeyID> || <PublicKey>
Where:
  - PublicKey: Ed25519 public key bytes (32 bytes)
  - KeyID: first 6 bytes of SHA256(<PublicKey>)
Validation on import: recompute KeyID from <PublicKey> and require equality.
Data:    Base64_RawURL( <Version> || <KeyID> || <PublicKey> )
String:  "PUB:" + <Data> + "\n"
```

### Signature (v1)

```
Prefix:  "SIG:"
Version: 1 byte (0x01)
Layout:  <Version> || <Check> || <KeyID> || <Signature>
Where:
  - Message: arbitrary byte sequence being signed (not included in the export)
  - Signature: Ed25519_Sign(PrivateKey, SHA512(<Message>)) (64 bytes)
  - KeyID: first 6 bytes of SHA256(<PublicKey>)
  - Check: first 6 bytes of SHA256(<KeyID> || <Signature>)
Data:    Base64_RawURL( <Version> || <Check> || <KeyID> || <Signature> )
String:  "SIG:" + <Data> + "\n"
```

#### Validation

- On import:
  - Validate prefix and Base64 decode succeeds.
  - Require `Version == 0x01` and minimal length.
  - Recompute `Check' = first 6 bytes of SHA256(KeyID || Signature)` and require equality with the embedded `Check`.
  - Note: Import does not perform cryptographic verification because the message is not part of the exported data.

- On verification:
  - Ensure the provided `KeyID` for provided <PrivateKey> equals `KeyID` from the signature (mismatch → invalid).
  - Verify Ed25519 signature: `Ed25519_Verify(<PublicKey>, SHA512(<Message>), <Signature>)` must be valid.
  
Notes:
- All “first 6 bytes” references are literal byte prefixes of the 32‑byte SHA256 digest.
- Base64 encoding is Raw URL variant (no padding characters).
