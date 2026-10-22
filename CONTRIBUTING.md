# Contributing to the m-sign specifications

Thank you for helping improve the specifications.

## Proposing a change

1. Open an issue that describes the problem and the proposed change before you write a pull request.
2. Classify the change:
   - **Editorial** (wording, typos, examples): no requirement changes. PATCH version bump.
   - **Normative** (adds or changes a MUST/SHOULD, or adds an item type): needs agreement in the issue first, new or updated test vectors, and a MINOR or MAJOR version bump.
3. The v1 byte format is frozen. A change that alters the bytes of an existing item type needs a new format version.

## Pull requests

- Update `CHANGELOG.md` under `[Unreleased]`.
- When you change the vectors, change `tools/vectors.py` and regenerate:

  ```sh
  python3 tools/vectors.py generate
  python3 tools/vectors.py verify
  ```

  CI fails if `test-vectors/v1.json` does not match the generator's output.
- Every MUST in `format.md` should be covered by a test vector.
- Use LF line endings (enforced by `.gitattributes`).

## Implementations

Changes that affect implementations should be coordinated with [m-sign/msign](https://github.com/m-sign/msign) and [m-sign/tools](https://github.com/m-sign/tools).

## Code of conduct

Participation is governed by the Contributor Covenant 2.1, as published in the [tools repository](https://github.com/m-sign/tools/blob/master/CODE_OF_CONDUCT.md).
