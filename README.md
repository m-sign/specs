# m-sign specifications

This repository holds the specifications of the m-sign signature formats.

m-sign signs files with Ed25519 and stores keys and signatures as short, single-line text items such as `PUB:AThuQYp3…` that are easy to copy into files, environment variables and CI secrets.

## Documents

| Document | Version | Status |
|---|---|---|
| [Data formats](format.md): private keys, public keys and signatures | 1.0.0 | Stable |
| [Test vectors](test-vectors/v1.json) for format v1 | 1.0.0 | Stable |

## Implementations

- [github.com/m-sign/msign](https://github.com/m-sign/msign): Go library.
- [github.com/m-sign/tools](https://github.com/m-sign/tools): the `msign` command-line tool.
- [tools/vectors.py](tools/vectors.py): stdlib-only Python reference used to generate and check the test vectors. It is not constant-time; do not use it with real keys.

An implementation conforms to format v1 when it reproduces every value in `keys` and `signatures`, rejects every `invalid` and `verify_invalid` case with the stated error class, and accepts the `accepted_variants`.

## Checking the test vectors

```sh
python3 tools/vectors.py verify               # check every vector against the reference implementation
python3 tools/vectors.py generate              # regenerate test-vectors/v1.json
git diff --exit-code -- test-vectors/          # generation is deterministic
```

## Versioning

Documents use semantic versioning:

- **MAJOR**: a new, incompatible format version (a new version byte).
- **MINOR**: new item types or optional features that existing readers can ignore.
- **PATCH**: editorial changes that do not change any requirement.

The v1 byte format is frozen. Releases are git tags such as `v1.0.0`. When you cite the specification, cite a tag.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues as described in [SECURITY.md](SECURITY.md).

The organization profile in `.github/profile/README.md` only takes effect in a repository named `.github`. It is kept here until that repository exists.

## License

[MIT](LICENSE)
