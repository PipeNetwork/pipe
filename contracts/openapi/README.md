These files pin the reviewed Pipe public HTTP contract release. `index.json` records the source revision, immutable download URLs and SHA-256 checksums. Tests read these local files; builds and commands never fetch mutable production specifications.

Run `cargo test --locked` to check REST requests/responses, signing/protocol fixtures, payment recovery, redaction and the pinned checksums. OpenAPI validation is a dev dependency. It does not replace the CLI's handwritten authentication, S3 transport, signing, encryption or payment journal.

To update, generate and qualify a release in the lattice repository, copy all three public JSON specifications and their index into this directory, review the semantic changes and run the full test suite. Keep the JSON files byte-identical to the immutable release. Private BFF, operator and internal specifications do not belong here.
