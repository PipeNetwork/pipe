# Storage bucket automation

Use a bucket's UUID for management commands and its returned S3 name for file
operations. Run `pipe storage buckets list --output json` to see both.

```sh
pipe storage buckets create 'Project media' --wallet LINKED_CREDIT_IDENTITY
pipe s3 setup --write --bucket S3_BUCKET_NAME
pipe s3 cp ./file.bin s3://S3_BUCKET_NAME/
pipe storage search invoice --extension pdf --min-bytes 1024 --all
pipe storage keys BUCKET_UUID create 'Build uploads' --permissions read,write,list --prefix builds/
pipe storage keys BUCKET_UUID list
pipe storage audit BUCKET_UUID
pipe storage requests
pipe storage resume REQUEST_UUID
```

Key secrets are hidden by default. Explicit `--show-secret` exports a recovered
secret. Keep it in a credential manager and out of shell history or logs. The
CLI saves mutation intent and returned secrets in encrypted, account-bound
journals before presenting success. A lost reply is resumed with its original
request ID; changing account or endpoint cannot reuse that intent.

## CORS

```json
{"revision":0,"rules":[{"allowed_origins":["https://app.example.com"],"allowed_methods":["GET","HEAD"],"allowed_headers":["*"],"expose_headers":["etag","content-range"],"max_age_seconds":300}]}
```

Read the current revision, then submit the complete replacement policy:

```sh
pipe storage cors BUCKET_UUID get
pipe storage cors BUCKET_UUID set --file cors.json
```

At most 20 rules, 20 origins per rule, 50 allowed headers and 50 exposed headers
are accepted. Origins are exact HTTP(S) origins or `*`; hostname wildcards are
unsupported. First-party PipeBox origins remain available for signed transfers.

## Webhooks

```sh
pipe storage webhooks BUCKET_UUID create https://events.example.com/storage --event object.uploaded --event object.deleted --prefix media/
pipe storage webhooks BUCKET_UUID deliveries
pipe storage webhooks BUCKET_UUID retry DELIVERY_UUID
pipe storage webhooks BUCKET_UUID revoke WEBHOOK_UUID
```

Destinations must use HTTPS on port 443, with publicly reachable DNS addresses.
Redirects, private addresses and proxy environment variables are not followed.
Each attempt has a 15-second deadline. Twelve automatic attempts use exponential
backoff from 5 seconds, capped at one hour; failed deliveries can be retried
manually. Manual retries preserve the delivery ID and exact event body. An
in-flight request may finish after revocation; queued requests are cancelled.

Validate `x-pipe-signature` before processing the raw body. Its value is `v1=`
followed by the hex HMAC-SHA256 of:

```text
<x-pipe-timestamp>.<x-pipe-delivery-id>.<raw request body bytes>
```

Use the UTF-8 bytes of the returned secret string as the HMAC key, without
hex-decoding that string. Use constant-time comparison, reject timestamps outside
your tolerance (for example five minutes), and durably deduplicate delivery IDs.
Retries receive a new timestamp and signature. `x-pipe-event-id` identifies the
publication shared by deliveries to multiple configured receivers. Event bodies
are versioned with `schema_version: 1` and preserve byte counts as strings.

## Lifecycle

```sh
pipe storage lifecycle BUCKET_UUID get
pipe storage lifecycle BUCKET_UUID preview --prefix logs/ --days 30
pipe storage lifecycle BUCKET_UUID enable --prefix logs/ --days 30 --revision REVISION --preview-token TOKEN --yes
pipe storage lifecycle BUCKET_UUID disable
```

One prefix/age rule is supported per bucket; the age is 1–36,500 days. Preview
returns the matching count, exact total bytes, up to 100 samples and a token valid
for ten minutes. Changes use revision checks and exact-response recovery.
Expiration permanently deletes the selected current publication; it is not
object versioning or Object Lock. A new upload receives a different version even
when its content is identical.

Workers persist version-specific intents, reconcile lost responses and use the
signed `x-pipe-if-version` S3 extension. A stale version returns 412. An unavailable
gateway or unresolved publication remains an unknown outcome, not success. The
settings view and CLI `get` include recent operation states and errors. Membership
loss prevents new privileged effects; reconfigure the rule under a current admin
to recover from a denied lifecycle credential.
