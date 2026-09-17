# Pipe CLI 3.0 release candidate

Pipe CLI covers browser and wallet login, scoped automation, accounts and organizations,
billing and payment recovery, storage, compute, hosting, KV and paid Durable Objects.
It preserves the existing storage signing, encryption and recovery formats.
The exhaustive [coverage manifest](contracts/coverage.json) assigns every public
operation a command, managed workflow, advanced call or explicit exclusion.
This is a release candidate; stable promotion requires the recorded production
acceptance checks and the five supported platform builds.

Browser login uses the existing Pipe account (Google or wallet) and requires a
matching backend with the optional `cli` schema, `LATTICE_PLATFORM_CLI_ENABLED=true`
and an explicit `LATTICE_PLATFORM_CLI_ACCOUNTS` allowlist. Those settings do not
apply migrations or open product launch gates automatically.

```sh
pipe auth login --no-browser
pipe context --output json
pipe doctor --output json
pipe compute vms list --limit 50
pipe kv instances
pipe durable namespaces
pipe hosting account
pipe api list
pipe api describe getComputeVm
pipe api call getComputeVm --path id=VM_UUID
```

`auth login` opens browser authorization by default; `--no-browser` prints the
URL and code for a remote terminal. Opening the link does not approve it. Use
`--scope "compute.read compute.write credentials.read credentials.write"` to
request explicit additional permissions. `auth login --wallet /private/key.json`
signs a platform challenge that binds its exact scopes and canonical account. Use
`--legacy-wallet` with `--wallet` only for a deployment supporting the preserved
storage-only wallet endpoints. No fallback to legacy authentication occurs automatically.

Automation can supply an activated `pcli_c_` credential through `PIPE_CLI_TOKEN`
without persisting it. Account keys, browser sessions and operator tokens are
rejected. Automation does not inherit a stored local wallet signing key.

New secrets require an OS keyring. On a headless machine, explicitly supply
`PIPE_CLI_SECRET_PASSWORD` (at least 12 characters) through your secret manager to
select the AES-GCM/Argon2id encrypted fallback. Keyring failures never create new
plaintext secret files. Existing legacy secret files remain readable; selecting
the encrypted fallback creates a private backup before migration. Keep that
backup private. Existing payment, multipart and transfer journals are preserved.

`--output json` emits one `{schema_version:1,result:...}` document. `jsonl` emits
one compact document per result; compute lists stream pages and operation waits
stream events. KV SCAN, Durable state/blob listings and platform billing history stream pages. Streaming for remaining products is pending. Legacy
`--json` remains available. Diagnostics stay on stderr. `--no-input` rejects
prompts; use `--yes` to confirm deletions, VM creation/lifecycle interruptions,
billing updates, recovery submissions, or payment submissions. Newly created
secrets are redacted unless `--show-secret` is explicitly supplied. Automation
credentials are saved before activation; resume an uncertain activation with
`pipe credentials activate ID`.

Configuration resolves explicit endpoint flags, `PIPE_CONTROL_API_URL`, the
selected profile, then `https://api.pipedev.network/control-api`. Explicit existing
endpoints remain unchanged. Storage discovers its gateway from the customer API;
the documented production default is `https://gw-001.pipedev.network`.

Current platform commands provide managed compute, KV, paid Durable Objects and
hosting workflows. `pipe api call` permits only reviewed reads, validates
parameters against the pinned OpenAPI 3.1 contract, and cannot target arbitrary
URLs or invoke payment mutations. Anonymous diagnostic calls never forward
credentials. See [billing workflows](docs/cli3-billing.md) and
[scoped automation](docs/cli3-automation.md). The candidate public release is pinned in `contracts/openapi`; the control-plane
request bindings also pin its identical document in `contracts/platform-draft`.
The previous pin is retained in `contracts/previous-openapi`. Release records bind
all checksums to the backend revision.

## Canonical accounts, organizations and billing

```sh
pipe account get
pipe account identities
pipe account wallets
pipe org list
pipe billing balance
pipe billing balance --org ORG_ID
pipe billing ledger --org ORG_ID --limit 100 --all
pipe billing usage --from 2026-09-01T00:00:00Z --limit 100 --all --output jsonl
pipe billing get ORG_ID
pipe billing invoices ORG_ID
pipe billing subscriptions ORG_ID
```

`account get` reads the canonical platform profile. The preserved bare `account`
command and explicit `account infrastructure` read infrastructure identities.
`billing` labels platform credits (USD 0.04 each) and the server's separate USD
fields. It never adds them to infrastructure credit or recalculates amounts using
floating point. Usage integers and application token details remain intact.
History accepts RFC3339 `--from`/`--to`, `--cursor`, `--limit` and `--all`; at most
100 pages are followed. A remaining cursor indicates more records, including when
the 16 MiB aggregate JSON bound stops collection. JSONL streams pages separately.
Usage totals describe the server's filtered query and must not be added across pages.

Organization billing requires `org.read` plus `billing.read` (or `usage.read`) and
current owner/admin/billing-admin membership. Default browser login requests these
read scopes. Mutations require explicit additional grants:

```sh
pipe auth login --scope "account.read account.write org.read org.write billing.read usage.read"
pipe account update --display-name "My Name" --yes
pipe org create "My Organization" --yes
pipe org members ORG_ID list
pipe org members ORG_ID update ACCOUNT_ID --role billing_admin --yes
pipe org invites ORG_ID create person@example.com --role member --yes
pipe org invites ORG_ID export REQUEST_ID --show-secret
pipe org accept --token-file /private/invitation.txt --yes
pipe org invites ORG_ID revoke INVITE_ID --yes
pipe org members ORG_ID delete ACCOUNT_ID --yes
pipe account referrals
pipe account rotate-referral --yes
```

Invitation secrets and exact mutation intent are encrypted before submission.
Invitation acceptance reads a private file; tokens never need to enter process
arguments. Sending an invitation does not send email. Export is explicit and
rechecks current organization access and invitation availability. Browser session
management and identity linking remain on the website; CLI sessions use `auth`.
Organization automation requires explicit organization bindings and current
membership. Account-bound automation cannot inherit current or future organization
memberships. Resource-bound grants restrict access to the selected VM, KV instance,
Durable namespace or hosting site. Account API keys and product credentials are separate credential types.

Unknown mutations exit 8 and remain in `account requests` (also `org requests`).
`account resume REQUEST_ID` only observes current state; it never repeats a mutation
or overwrites a later member role/profile setting. Observed state is labeled separately
from a server receipt. Ambiguous invite acceptance and referral rotation require
inspection and explicit `account acknowledge REQUEST_ID --yes` once resolved.
Pending requests prevent replacement mutations for the same account and endpoint.
Organization creation grants no credit. Hosted checkout, billing settings and
legacy Solana payment recovery use the dedicated [billing workflows](docs/cli3-billing.md).

## Account API keys

These legacy keys grant account API access. Use `pipe credentials` for scoped CLI
automation instead. Listing requires `credentials.read`; creating or changing a
key requires an interactive CLI session with both `credentials.write` and
`billing.write`. Revocation needs `credentials.write`. Automation credentials
cannot create, update or revoke legacy account keys.

```sh
pipe auth login --scope "account.read credentials.read credentials.write billing.write"
pipe account keys list
pipe account keys create --label batch --hard-cap-usd 10 --daily-cap-usd 2 --yes
pipe account keys export KEY_UUID --show-secret
pipe account keys update KEY_UUID --clear-daily-cap --no-retention true --yes
pipe account keys update KEY_UUID --disabled true --yes
pipe account keys revoke KEY_UUID --yes
```

Key material and the original settings are encrypted locally before activation.
Creation output never includes the secret; export requires `--show-secret` and
rechecks that the saved key is still active in the same account. Retain this
profile's encrypted state to export its keys later. Disabling or revoking a key
blocks export. The server preserves its existing last-key revocation protection.

Omitted settings retain their value. `--clear-label`, `--clear-hard-cap`,
`--clear-daily-cap` and `--clear-models` explicitly clear settings; repeated
`--allowed-model MODEL` sets the model allowlist. Caps are the legacy API's USD
limits, distinct from integer payment amounts. The CLI transmits decimal inputs
without float conversion; the existing server represents these limits as floats.
Recovery compares decimals without rounding a difference away.

If a response is lost, use `account requests` and `account resume REQUEST_ID`.
Recovery observes current settings without resubmitting a creation, cap change or
revocation. Later changes can leave the original outcome unresolved; inspect it
before explicitly acknowledging it. Existing spend counters and key hashes remain
intact. These commands do not transfer funds.

## Compute workflows

Sign in with `compute.read compute.write` and add `billing.write` for paid VM
creation or renewal changes. Discover eligible projects, images, flavors and
current pricing before creating a VM. Existing launch and capacity gates apply.

```sh
pipe compute projects
pipe compute images
pipe compute pricing
pipe compute vms create --project PROJECT_UUID --name dev --image IMAGE_ID \
  --flavor PLAN_ID --ssh-key ~/.ssh/id_ed25519.pub \
  --price-version CURRENT_VERSION --auto-renew false --yes
pipe compute vms list --all --output jsonl
pipe compute vms get VM_UUID
pipe compute vms stop VM_UUID --wait --timeout 300 --yes
pipe compute vms start VM_UUID --wait
pipe compute vms reboot VM_UUID --yes
pipe compute vms billing VM_UUID --price-version CURRENT_VERSION --auto-renew false --yes
pipe compute vms delete VM_UUID --yes
```

Paid creation reserves existing credit. Stopped VMs retain their monthly billing;
deleting a VM destroys its disk and cancels renewal without refunding unused paid
time. Pilot flavors omit both price and renewal flags. Private SSH keys are never
uploaded by the create command.

Every mutation saves its exact body and idempotency key in a private, versioned
profile journal before sending. An uncertain outcome exits with status **8** and
prints its request ID. Run `pipe compute requests` and
`pipe compute resume REQUEST_UUID --yes` to reconcile it. Resume verifies the
original endpoint and owner/account context; it never creates a replacement key.
Reusing `--request-id` with a changed request is rejected. Accepted receipts are
retained across login and subsequent runs. `--wait` timing out exits with status
**9**; server work can continue. Inspect `pipe compute operations OPERATION_UUID`.

`pipe compute ssh VM_UUID --identity-file ~/.ssh/id_ed25519` uses installed
OpenSSH and requires the API's SHA-256 host fingerprint. Initial key discovery is
checked against that fingerprint before saving a profile-specific known-host
record. Missing or conflicting identity fails closed; a changed saved identity
requires investigation. OpenSSH's strict host checks remain enabled; local SSH
config, proxies, forwarding and connection multiplexing are excluded from this
API-directed connection. See the [OpenSSH manual](https://man.openbsd.org/ssh).
Use `--command 'uname -a' --no-input` for remote command execution. SSH streams
remote output in table mode and propagates its exit status, including 255 for an
SSH connection failure. It never evaluates the advertised `ssh.command` string
in a local shell.

The workspace has `pipe-api` for reviewed typed REST models and request builders,
`pipe-transports` for verified data connections, and the root CLI for session,
state and presentation. Additional product modules and state extraction remain
in progress. Run `cargo test --locked --workspace`. The optional OpenSSH integration
fixture requires a disposable local sshd:
`PIPE_TEST_SSHD=/usr/sbin/sshd cargo test --locked -p pipe-transports -- --include-ignored`.

## KV workflows

Request `kv.read kv.write credentials.write` at login for instance and credential
management. Key creation also requires the product permissions being delegated.
An existing KV product credential can be imported without a browser session.
Existing launch gates and prepaid storage-credit checks remain in effect.

```sh
pipe kv pricing
pipe kv instances list
pipe kv instances create --wallet CREDIT_WALLET --yes
pipe kv credentials create INSTANCE_UUID --permissions 3 --label terminal --yes
pipe kv connection CREDENTIAL_UUID
pipe kv set greeting --value hello --credential CREDENTIAL_UUID
pipe kv get greeting --credential CREDENTIAL_UUID
pipe kv mget greeting missing --credential CREDENTIAL_UUID
pipe kv incr counter --by 1 --credential CREDENTIAL_UUID
pipe kv expire greeting 60 --credential CREDENTIAL_UUID
pipe kv scan --all --count 128 --credential CREDENTIAL_UUID --output jsonl
pipe kv credentials revoke CREDENTIAL_UUID --yes
pipe kv instances delete INSTANCE_UUID --yes
```

Creation saves random resource IDs and credential material before sending. Use
`--request-id UUID` for a chosen durable management intent, or inspect
`pipe kv requests` and run `pipe kv resume REQUEST_UUID --yes` after an uncertain
response. The matching backend preserves IDs and hashes on exact retries;
revocation and deletion cannot be undone by replay. Earlier servers that lack
these optional request fields need the matching backend update. Existing browser
clients can continue requesting server-generated material.

Data connections use the advertised `rediss://` endpoint and verified TLS with
credential-ID/secret authentication. `PIPE_KV_CREDENTIAL` selects a saved product
credential. Data commands authenticate with that explicitly selected product key,
independently of the browser/CLI session. Imported key permissions remain unknown
until enforced by the service. Additional CA certificates use `--ca-cert` or `PIPE_KV_CA_CERT`;
hostname verification remains required. Import existing material with
`pipe kv credentials import ID --secret-file /private/secret --endpoint rediss://HOST:6380`.
Inspect/export it with `pipe kv credentials export ID`; the secret is included
only with `--show-secret`. Secrets never appear in connection URLs or arguments.

Values and keys are binary safe. Use `set --value-file FILE` (`-` reads stdin),
`get --destination FILE` for an atomic download into a new file, and
`--base64-keys` for arbitrary key/MATCH bytes. JSON values contain `base64` and
`bytes`; missing values are null. Counter/expiry integer results are decimal
strings, preserving signed 64-bit precision. The
[RESP2 protocol](https://redis.io/docs/latest/develop/reference/protocol-spec/)
implementation is restricted to Pipe's implemented GET/SET/MGET/DEL/EXISTS,
SCAN, counter, expiry and persistence operations. Frames, values, keys, scan
pages and responses are bounded; SCAN returns its resumable cursor and `complete`.

A forwarded data mutation is sent once. A lost response or a server `UNKNOWN` or
`COMMITTED` error exits **8**, preserving an unresolved request and its payload
hash. Inspect the data before recording `pipe kv acknowledge REQUEST_UUID --yes`.
Acknowledgement retains the uncertainty and never replays the command. An
identical unresolved intent blocks another submission until acknowledged.

KV state uses a versioned AES-GCM encrypted file with a separate random key in
the selected OS keyring or explicitly encrypted fallback. It preserves credentials
and recovery records across login and profile changes, keeps application values
out of journals, and refuses corrupted or unsupported state. Back up both the
state directory and its secret-store material for recovery.

Run the actual CLI against the disposable production router/node/executor
fixture after building the backend example with `kv-test-fixture`:

```sh
PIPE_KV_FIXTURE=/path/to/lattice/target/debug/examples/kv_gateway_fixture \
  python3 scripts/test-kv-workflow.py
```

This fixture uses loopback TLS and synthetic authority. It does not qualify
production launch gates or spend production credit.

## Durable Objects workflows

These commands use the existing paid customer Durable Objects APIs. Login needs
`durable.read` for reads and `durable.write` for writes; namespace creation and
spending-limit changes also require `billing.write`. Key management requires
`credentials.write`, and creation also requires `durable.read` to delegate read
access. Existing launch gates, identity ownership and prepaid-credit limits
remain in effect. Reads are paid requests too.

```sh
pipe durable pricing
pipe durable namespaces create --wallet CREDIT_WALLET --name app \
  --price-version PRICE_VERSION --spending-limit-atoms 1000000 --yes
pipe durable credentials create NAMESPACE_UUID --label worker --write --yes
pipe durable state put settings --value-file settings.json \
  --namespace NAMESPACE_UUID --object app --wait
pipe durable state get settings --namespace NAMESPACE_UUID --object app --wait
pipe durable sql --statements-file statements.json \
  --namespace NAMESPACE_UUID --object app --wait
pipe durable migrate 1 --statements-file migrations.json \
  --namespace NAMESPACE_UUID --object app --wait --yes
pipe durable blobs put asset --file asset.bin --namespace NAMESPACE_UUID --object app --wait
pipe durable blobs get asset --destination downloaded.bin --namespace NAMESPACE_UUID --object app
pipe durable state list --all --namespace NAMESPACE_UUID --object app --output jsonl
pipe durable objects NAMESPACE_UUID
pipe durable activity NAMESPACE_UUID
```

SQL input is an array such as `[{"sql":"SELECT ?","params":[42]}]`; migration input
is an array of SQL strings. State values accept arbitrary JSON, including null,
large integers and fields named `secret` or `token`. Application results preserve
these fields; credential and session output remains redacted. Binary results are
base64 in JSON or written atomically to an explicit new destination. Request and
response sizes are bounded by the pinned contract. State/blob listings support
`--prefix`, `--after`, `--all` and `--max-pages`; activity is the server's latest
50 records with `has_more`, without inventing a historical cursor.

Use `--credential CREDENTIAL_UUID` for a separately authenticated namespace key.
Import one with `pipe durable credentials import ID --namespace NAMESPACE_UUID
--secret-file /private/key`; other credential types are rejected. Export uses
`pipe durable credentials export ID --show-secret`. New keys are random and saved
securely before activation; exact retries reuse the ID and secret without extending
expiry or reactivating revoked keys. They remain bound to this profile endpoint
and namespace across login.

Every submitted action saves its original body and idempotency key in an encrypted
journal. Operations return an ID immediately; `--wait --timeout SECONDS` waits to
a deadline, exiting **9** while server work can continue. Inspect
`pipe durable operation OPERATION_UUID --wait`. Unknown submission outcomes exit
**8**: inspect `pipe durable requests`, then run
`pipe durable resume REQUEST_UUID --wait --yes`. Recovery reuses the original
payload, credential and key, avoiding replacement operations and duplicate charges.
Completed application failures return a single JSON error document and exit **1**;
expired server results exit **8**, preserving the operation ID and accounting.

Spending-limit updates lack a server idempotency receipt. After a lost response,
resume reads the current setting and never overwrites a later decision. If it
cannot reconcile, inspect the namespace before explicitly recording
`pipe durable acknowledge REQUEST_UUID --yes`. That records uncertainty without
replaying the change. Delete an object with `pipe durable delete-object` and the
same namespace/object flags, then revoke the namespace with
`pipe durable namespaces delete ID --yes`. Pending paid work prevents namespace
revocation until it is reconciled.

Durable journals use versioned AES-GCM encryption, with their key in the selected
secure store. Back up both; original payloads and results are required for recovery.
The disposable qualification harness in the backend repository is
`scripts/test-customer-durable.py --test-filter platform_cli_real_storage_workflow
--cli-binary /path/to/pipe` (supply its explicit loopback PostgreSQL/source/target
arguments). It uses the actual CLI, control plane and three private storage
replicas with synthetic credit. It does not qualify production launch readiness.

## Hosting workflows

Hosting uses the existing customer control-plane APIs and private host transport.
Login requires `hosting.read hosting.write`; paid plan purchases additionally
require `billing.write`, and deployment-key management requires
`credentials.write`. Creating a key also requires the read permission it delegates.
Product keys authenticate only the hosting site APIs. They cannot purchase plans
or create other credentials.

```sh
pipe hosting pricing
pipe hosting account register --wallet CREDIT_WALLET
pipe hosting plans purchase starter --price-version PRICE_VERSION --yes
pipe hosting sites create --slug my-app
pipe hosting deploy SITE_UUID --bundle app.zip --expected-active none --migrate --yes
pipe hosting sites get SITE_UUID
pipe hosting sites logs SITE_UUID
pipe hosting releases list SITE_UUID
pipe hosting domains create SITE_UUID app.example.com
pipe hosting domains verify SITE_UUID DOMAIN_UUID
pipe hosting billing
```

Bundle input is an existing `application/zip` artifact (maximum 32 MiB). It is
copied into an encrypted local snapshot before upload; its SHA-256 is the release
ID. `deploy` saves a deployment ID and separate upload/migration/activation intents
before sending. `--migrate` explicitly applies the selected release's SQLite
migrations. `--expected-active none` requires a stopped site; use the current
release hash when updating. Owner and arbitrary database assignment stay outside
customer commands.

A deployment has a bounded `--timeout` (default 300 seconds). Unknown outcomes
exit **8**, and wait deadlines exit **9** without cancelling server work. Inspect
`pipe hosting requests` and run `pipe hosting resume REQUEST_OR_DEPLOYMENT_UUID
--yes`. Recovery uses the saved bundle even if the source file changed or was
removed. It preserves completed steps and account/credential bindings. Unresolved
deployments prevent replacement intents for the same site.

Purchases retain exact terms and idempotency keys; pending receipts support
`--wait`. Hosting credentials save random IDs/secrets before
activation and preserve expiry on exact retries. Create one with
`pipe hosting credentials create --label ci --write --yes`, then select its ID
using `--credential ID` or `PIPE_HOSTING_CREDENTIAL` on site commands. Existing
keys can be imported with `credentials import ID --account HOSTING_ACCOUNT_UUID
--secret-file /private/key`. Export requires `credentials export ID --show-secret`.
Credentials remain separate from browser/CLI sessions and operator tokens.

After uncertain activation, deactivation, allocation or domain operations,
recovery observes current state without repeating a mutation that could overwrite
a later decision. If observation cannot reconcile it, inspect the service and
use `pipe hosting acknowledge REQUEST_UUID --yes` to record the uncertainty.
Purchase, upload, registration, credential activation, deletion cleanup and
immutable migration recovery retain their documented retry rules. Reconciliation
is reported explicitly; absent site state does not prove background cleanup
completed.

Dedicated commands also support `releases upload/delete`, `sites
activate/deactivate/migrate/storage/delete`, and `domains list/delete`. Release
and domain deletion respect the server's ownership and active/rollback protection.
Site deletion returns cleanup status, with `--wait` for pending cleanup. Hosting
lists use the server's bounded response and logs are its current 64 KiB tail;
these APIs do not expose pagination cursors. Back up the encrypted state and its
secret-store key, including saved deployment bundles, for recovery.

The backend's `scripts/test-cli-hosting.py` runs the actual CLI, control plane,
private host, Spin, SQLite and loopback DNS with synthetic credit. Supply the
explicit PostgreSQL URL, binaries and evidence directory. Production cgroup,
filesystem-quota, TLS, browser and launch qualification remain separate release
requirements.

## Install

Use the stable Rust toolchain and a C build toolchain:

```sh
cargo install --locked --path .
pipe --help
```

`./setup.sh` installs this checkout; `./setup.sh --force` replaces an installed
binary without deleting source files or configuration. CI builds and tests on
Linux, macOS, and Windows.

## Server requirement

Platform browser and wallet login require the additive `migrate-cli` schema
(version 2), runtime grants, and qualification-account admission described above.
The installer preserves a checksummed version 1 installation while adding wallet
challenges. It never runs unrelated main migrations. Legacy `--legacy-wallet`
requires the separate migration `0026_customer_cli_sessions.sql` and
`LATTICE_CUSTOMER_CLI_ENABLED=true`. Configure `LATTICE_S3_ENDPOINT` and
`LATTICE_S3_REGION` for gateway discovery. This checkout does not deploy or enable
these routes in production. Automatic read onboarding also requires the additive
`POST /v1/customer/cli/s3/session` route, which accepts `storage.read` and emits
only a short-lived read/list credential; permanent write keys retain the existing
credential-management permission requirements.

## First upload

```sh
pipe profile create personal --control-api-url https://api.pipedev.network/control-api
pipe profile use personal
pipe auth login --wallet /private/keypair.json --scope "account.read storage.read storage.write usage.read credentials.write"
pipe payments config
pipe payments create 10.00
# Use the invoice_id returned above. This command signs and submits the payment.
pipe payments pay INVOICE_ID --yes
pipe payments status INVOICE_ID
# Wait until the invoice is credited before storage setup. Read-only listing
# can create a short-lived key automatically; writes require explicit setup.
pipe s3 endpoint
pipe s3 setup --bucket my-bucket
pipe s3 setup --write --bucket my-bucket
pipe bucket create my-bucket
pipe object put ./file.txt my-bucket/file.txt
pipe object get my-bucket/file.txt ./downloaded.txt
pipe credits
pipe usage
```

Both platform and compatibility wallet login can use an existing keypair.
Fund that address with USDC and sufficient SOL for the transaction fee before
creating a payment. To use an existing wallet, use `pipe auth login --wallet
/path/to/keypair.json`. Solana 32/64-byte JSON arrays and files containing a
32-byte hex secret (plain text or `secret_key_hex`) are accepted. Private keys
and encryption passwords are never command-line arguments.

`payments pay` signs only an invoice previously saved by this profile. It checks
the requested amount and wallet, mainnet USDC, recipient token account, memo,
transaction instructions and fee limits before using the local key. For an
external payer, use `payments create --payer SOLANA_ADDRESS`, sign outside the
CLI, then use `payments submit INVOICE_ID --transaction BASE64` or `--signature
SOLANA_SIGNATURE`. Neither value is a wallet private key.

## Recovery and payments

Each payment intent is saved privately before the first request. Its recovery
UUID is printed to stderr and returned as `idempotency_key` on success. Repeating
`payments create` with the same amount/payer reuses an unresolved intent. You can
also pass `--idempotency-key UUID`. Never choose a new key just because a response
was lost. Status accepts a known invoice ID or its saved recovery UUID.

`payments pay` saves the signed transaction before submission and reuses exactly
those bytes after interruption. It does not generate a replacement payment.
Use `payments status` to inspect confirmation or reconciliation progress.

For an x402 signer, `payments create-x402 AMOUNT` negotiates the current
`/v1/payments/topups` contract and saves its exact requirements. Submit an
externally signed x402 v2 payload with `payments submit-x402 INVOICE_ID
--payload-file FILE`. The file may contain JSON or a base64 `PAYMENT-SIGNATURE`
value; its terms must match the saved invoice.

## Profiles and credentials

```sh
pipe profile list
pipe profile use personal
pipe profile show
pipe profile set --bucket my-bucket --prefix backups/
pipe --profile personal config show
pipe auth sessions
pipe auth status
pipe auth sessions --revoke SESSION_UUID
pipe auth logout
pipe s3 setup --bucket my-bucket
pipe s3 setup --bucket my-bucket --wallet STORAGE_WALLET
pipe s3 setup --write --bucket my-bucket --expires-in 2592000
pipe storage init --bucket my-bucket
pipe s3 credential list
pipe s3 credential rotate ACCESS_KEY_ID
pipe s3 credential revoke ACCESS_KEY_ID
pipe s3 ls
pipe s3 ls s3://my-bucket/backups/
pipe s3 cp ./file.txt s3://my-bucket/file.txt
pipe s3 cp s3://my-bucket/file.txt ./file.txt
pipe s3 sync ./local s3://my-bucket/backups/
pipe s3 rm s3://my-bucket/file.txt
pipe s3 mb my-bucket
pipe s3 rb my-bucket
```

`pipe s3 setup` is an explicit action and creates the credential immediately;
it does not ask for a second confirmation. It also saves the selected bucket and
explicit prefix as the profile defaults, so a later `pipe s3 ls` uses that
bucket without trying global bucket discovery. Read-only S3 commands can also
create their short-lived read/list credential automatically. Destructive commands
and payment submissions still require their normal confirmation.

Profiles contain only the control API URL, S3 endpoint, region, bucket and prefix
defaults. `--config FILE` selects a separate configuration. Sessions and keys are
scoped to the configuration/profile and control API endpoint. A command lock
prevents simultaneous session refreshes for one profile.

Native OS keyrings are enabled. Set `PIPE_CLI_SECRET_PASSWORD` to explicitly
select encrypted fallback storage when the keyring is unavailable.
`PIPE_DISABLE_KEYRING=1` disables the native keyring but does not authorize
plaintext secret persistence. Profile state lives under the OS config
directory's `pipe` folder; it includes payment journals and transfer recovery
records. Preserve this state when recovering an interrupted payment.
`PIPE_CLI_STATE_DIR` selects a different private state directory for automation.

Each command caches secret lookups for its lifetime, so a macOS Keychain item is
opened at most once per command. A denied or locked Keychain lookup is latched
for that command instead of being retried for every API request. New active S3
credentials are stored as one item, which avoids separate Keychain prompts for
the access key and secret. If the Keychain is unavailable, explicitly choose
the encrypted fallback with `PIPE_DISABLE_KEYRING=1` and a password of at least
12 characters.

New S3 secrets are saved before local use and are exported only with `--show-secret`.
Rotation creates and stores a replacement before revoking the old key; a failed
revocation is reported explicitly. `s3 credential import ACCESS_KEY_ID` securely
prompts for an existing S3 secret, and `s3 credential use ACCESS_KEY_ID` selects a
stored key. Configure the same endpoint, bucket and key to access existing
PipeBox objects. No bucket or object migration is performed. If a read-only
command such as `s3 ls`, `s3 head`, or `object list` has no local key, the CLI
offers to create a seven-day `read/list` credential for the requested bucket,
saves it in the OS keyring, and retries the original request once. This prompt
never grants write access. Use `s3 setup --write` for uploads, deletes, bucket
creation, or other mutations; `--no-input` prints the setup command instead.

`pipe config migrate --legacy-path FILE` creates a timestamped private backup
and imports compatible local configuration fields. It discards legacy
authentication fields and uses the current default control API unless an
explicit `control_api_url` is present.

## Objects and directories

```sh
pipe bucket head my-bucket
pipe object list my-bucket prefix/
pipe object head my-bucket/file.txt
pipe object put ./file.txt my-bucket/file.txt --if-none-match '*'
pipe object get my-bucket/file.txt ./part.bin --range 0-1048575
pipe object get my-bucket/file.txt ./file.txt --if-match 'OPAQUE_ETAG'
pipe object delete my-bucket/file.txt
pipe upload-directory ./local my-bucket backups
pipe download-directory my-bucket backups ./restored
pipe sync ./local s3://my-bucket/backups
pipe sync s3://my-bucket/backups ./restored
```

`upload-file` and `download-file` are aliases for object put/get. Explicit
locations accept `bucket/key` or `s3://bucket/key`. A bare filename uses the
profile's bucket and prefix. `bucket list` and its `s3 ls` shortcut report the
configured bucket after HEAD; `s3 ls s3://BUCKET/PREFIX` lists objects under a
prefix. Pipe does not support global `ListBuckets` enumeration, so no-argument
`s3 ls` cannot discover every bucket in an account. Use `object list` for the
explicit form. `s3 cp` handles one file in either direction and directory
transfers with `--recursive`; `s3 sync` is the familiar spelling for the
existing top-level `sync` workflow. `s3 rm --recursive` deletes each listed
object under a prefix and uses the existing destructive confirmation.

`pipe doctor` reports endpoint configuration, whether an active storage key is
present, and whether its secret is available locally. The gateway currently has
no global `ListBuckets` operation, so automatic setup always scopes a key to the
configured or explicitly supplied bucket.

Sync records local content digests and observed opaque remote ETags to skip
unchanged files on later runs. It never deletes unrelated objects or local
files. Directory downloads reject traversal and symlink paths. Downloads are
committed atomically so a failed transfer preserves an existing destination.

The S3 client uses path-style SigV4 with an explicit region, fixed payloads and
signed AWS streaming chunks. Progress appears on stderr for interactive
transfers. Explicit ranges are limited to 32 MiB. ETags are opaque; no AWS MD5
multipart ETag calculation is used. Batch deletes, checksum trailers,
versioning, lifecycle rules, server-side encryption, object lock and KMS are
not requested. Server `NotImplemented` responses remain errors.

## Multipart uploads

Files of at least 8 MiB use multipart uploads. Content-bound manifests and the
upload ID allow reuse of verified parts. A manifest also records the exact
completion request for recovery after a lost completion response. Without a
matching manifest, existing parts are reuploaded rather than assumed correct
from their size. The client uses 8 MiB parts and at most 10,000 parts (about
78 GiB per object). Uploads use bounded-memory snapshots; allow temporary disk
space equal to the source size, or up to twice that for sync or encryption.

```sh
pipe upload-file ./large.bin my-bucket/large.bin --upload-id UPLOAD_ID
pipe s3 multipart list my-bucket
pipe s3 multipart parts my-bucket/large.bin UPLOAD_ID
pipe s3 multipart complete my-bucket/large.bin UPLOAD_ID
pipe s3 multipart abort my-bucket/large.bin UPLOAD_ID
```

On interruption, preserve the source and profile state, then resume using the
reported upload ID. A failed ordinary PUT is not reported successful merely
because an older object exists. Inspect the object before retrying an unknown
write outcome. Multipart upload parts have bounded retries; completion failures
preserve recovery state for an explicit retry or abort.

## Client-side encryption

```sh
pipe object put --encrypt ./secret.txt my-bucket/secret.txt
pipe object get --decrypt my-bucket/secret.txt ./secret.txt
```

Passwords are prompted without echo. Automation can use `--password-file FILE`.
Keep the password independently: it is never sent to Pipe. The versioned format
uses Argon2id and streaming AES-256-GCM, authenticating the header, encrypted
length metadata, every chunk and a mandatory final record. See
[CRYPTO_FORMAT.md](CRYPTO_FORMAT.md). Truncation, corruption and wrong passwords
fail without replacing the destination. Decryption requires the complete object,
so `--decrypt` cannot be combined with `--range`.

Interrupted encrypted uploads keep the original ciphertext in private profile
state. Resume with `--encrypt --upload-id UPLOAD_ID` and the unchanged source;
the exact ciphertext is reused. Successful transfers clean up that spool.

## Automation and verification

`--json` applies to every command. Normal output recursively omits secret fields;
create/rotate are the explicit exceptions for a newly issued S3 secret. Object
list emits one JSON document per page. Failed commands return a nonzero exit
status; JSON mode includes an error document. Progress and recovery notices go
to stderr. HTTPS is mandatory for configured endpoints, except loopback HTTP
for local testing. Redirects are disabled.

```sh
cargo fmt --check
cargo test --locked
cargo build --locked --release
```

Tests include wallet/session contracts, payment recovery and transaction
validation, SigV4 vectors, streaming and multipart S3 fixtures, conditional
requests, atomic downloads, sync and encryption corruption cases. Backend
session tests additionally require a disposable PostgreSQL database. Live
deployment, real USDC settlement and production bucket canaries are separate
deployment checks; local tests do not establish production availability.

The old Firestarter JSON endpoints, `new-user`, `user_app_key`, node payments,
deposits, referrals, priority tiers, public-link commands and experimental
post-quantum modes are removed.

## Configuration recovery and diagnostics

`pipe config backup /private/pipe-config.json` creates a versioned private backup.
`pipe config rollback /private/pipe-config.json --yes` verifies it and saves the
current configuration before restoring settings. Secrets and recovery journals
retain their current state, including unresolved payment and transfer records.

`pipe doctor --export /private/pipe-diagnostics.json` explicitly writes a private
report with platform availability flags, client version, OS, architecture and
journal file sizes. It excludes tokens, account identifiers and journal contents. Client
telemetry is off; the report is never uploaded automatically.
