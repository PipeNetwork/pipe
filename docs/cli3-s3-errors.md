# S3 error propagation correction

This source change is prepared after `v3.0.0-rc.1`. It is not included in the
published RC1 binaries or their production qualification record. It requires a
separately reviewed release.

S3 failures retain their HTTP status and recognized S3 error code through upload
and multipart context messages. JSON and JSONL error documents add `http_status`
and `s3_code`; human diagnostics also include these safe details. Server response
messages, arbitrary error cause chains, headers and signing material are not
printed.

Definitive HTTP 401, 403, 409/412 and unavailable responses use the existing
authentication (3), authorization (4), conflict (6) and unavailable (5) exits.
HTTP 402 uses `payment_required` with the existing general failure exit 1. A
submitted mutation with a lost response, transient server failure or unusable
acknowledgment reports `unknown_outcome` and exit 8. An earlier ambiguous attempt
within the same retry sequence remains unknown if a later attempt is refused.
A first-attempt authorization or precondition refusal remains definitive.
Ordinary read transport errors retain exit 7.

Retry counts, request signing, uploaded bytes, multipart identities, manifests
and completion replay remain unchanged. A single PUT is not automatically
replayed or declared successful from an unrelated HEAD response. Multipart
recovery retains the original upload ID, part list and conditions. Existing
manifest formats are unchanged; this correction does not reconstruct outcome
history that an older binary did not record. Keep an earlier unknown outcome
under investigation even if a later, separately invoked request is refused.

These error corrections do not resolve the independently recorded public-edge
HEAD and range failures. No paid production calls are needed to test them.
