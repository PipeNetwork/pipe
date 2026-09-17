# S3 write authorization verification — 2026-09-17

Implementation: `b7b677a6d0961b6c9637a6f29c531eb002073bbc`.

The default browser login has read scopes. S3 credential management requires
`storage.write` and `credentials.write`. Explicit write setup now starts browser
approval for the missing scopes, preserves existing grants, verifies the owner
and canonical account before replacing the session, and continues credential
creation. Noninteractive setup returns an actionable authorization error.

The executable regression starts with a read session, verifies that no-input
setup sends no request, rejects a different canonical account, then approves the
correct account and uploads/downloads binary data through the saved credential.
Bucket URI forms and relative download destinations are exercised. Error tests
preserve structured 403 status and unknown-outcome markers.

All 140 workspace tests passed; the opt-in OpenSSH fixture was not rerun.
Clippy, formatting and deterministic coverage checks passed. No public operation
was removed; the manifest records all 210 operations. The read-bootstrap POST
is correctly classified as a non-replayable credential mutation.

Real browser approval and write setup passed against the deployed control API.
The public test passed bucket creation, list/head, file upload/download, range,
conditions and recursive copy. It stopped at sync: a signed HEAD for a `.bin`
key reached the origin as GET and failed signature authentication. Nginx logs
confirmed the method conversion. Cloudflare documents this behavior for cacheable
HEAD requests: https://developers.cloudflare.com/cache/concepts/cache-behavior/.

A separate campaign through the production origin, retaining TLS certificate
and hostname verification, passed all 31 checks, including recursive copy, sync
in both directions, unchanged-file skipping, a 9 MiB multipart round trip,
credential rotation/use/revocation and cleanup. These origin results do not
qualify the public cache path. No global DNS, admission, backend binary, schema,
account ownership, or customer resource was changed.

PostgreSQL independently attributed 181 USDC atoms ($0.000181) to the test keys.
It reported zero live objects, active credentials/sessions, open credit leases,
or pending reservations. The original persistent $100 budget now records
$45.000581 spent and $54.999419 remaining; no funds were added or transferred.

The signed-S3 cache-bypass rule and guarded deployment script are already
prepared in the Lattice repository. Applying it requires Cloudflare configuration
access, which was unavailable during this verification. Full public-path
qualification remains incomplete. See [results.json](results.json).
