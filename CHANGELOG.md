# Changelog

All notable changes to the m-sign specifications are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and documents use [semantic versioning](README.md#versioning).

## [Unreleased]

## [1.0.0] - 2026-10-21

The v1 byte format is unchanged. Every existing key and signature stays valid.

### Added

- Normative language (BCP 14), document status and version, and normative references.
- Byte layouts with offsets and exact lengths for every item type.
- Text-encoding rules: grammar, canonical base64url, and reader handling of CRLF and a missing final newline.
- Private-key validation on import: KeyID must match the public key, and the public key must match the seed.
- An exact definition of the signing algorithm: PureEdDSA Ed25519 over the SHA-512 digest, which is not Ed25519ph.
- Versioning and extensibility rules, including the *unsupported version* error.
- Security considerations.
- Test vectors (`test-vectors/v1.json`) and an independent reference implementation (`tools/vectors.py`).

### Changed

- Check is now defined as the SHA-256 of all payload bytes after the Check field. The previous wording could be read as hashing KeyID twice. This is the same value the existing implementation computes.
- "Minimal length" is replaced by exact lengths: readers must reject trailing data.
