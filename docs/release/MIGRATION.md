# Migrating to Pipe CLI 3.0

This guide covers the 1.0.0 command interface at `b18eb5d` and existing profile/state files when upgrading to `3.0.0-rc.3`. Keep the previous binary and private local state until outstanding operations are resolved. Run `pipe doctor --output json` to inspect the deployment's supported, enabled and authorized features.

When upgrading from RC1, account for the corrected S3 error reporting in automation. A definitive `403` now reports `authorization` with exit `4`, and a definitive `409` or `412` reports `conflict` with exit `6`. Versioned output includes `result.error.http_status` and `result.error.s3_code`; streaming upload failures also retain those details. Unknown submitted mutations take precedence and return exit `8`, even if a later retry receives a refusal. Reconcile the original operation before retrying it. RC2 preserves existing signing, retry counts, ciphertext, profiles, secret storage and operation journals, so the version update requires no state conversion.

| Previous command | Current command or workflow |
| --- | --- |
| `wallet-auth --keypair FILE` | `auth login --wallet FILE` |
| `logout`; `sessions --revoke ID` | `auth logout`; `auth sessions --revoke ID` |
| `profile` / `whoami` | `profile show` / `whoami`; use `account infrastructure` or `account get` for detailed identity |
| `credits-status` / `check-deposit` / `credits` | `credits` for the selected infrastructure balance |
| `usage` / its former `billing` alias | `usage`; use `--from` and `--to` instead of `--period`/`--detailed` |
| `s3-key-create`; `s3-key-list`; `s3-key-delete ID` | `s3 credential create`; `s3 credential list`; `s3 credential revoke ID --yes` |
| `s3-info` | `s3 endpoint` |
| `--api URL`; `config set-api URL` | `--control-api-url URL`; save a compatible endpoint with `profile create NAME --control-api-url URL` |
| S3 configuration setters | `profile create NAME --s3-endpoint URL --region REGION --bucket BUCKET --prefix PREFIX` |
| `topup`, `credits-intent`, `credits-submit`, `sync-deposits` | Inspect `payments --help` and the [billing workflows](../cli3-billing.md). Old intent IDs are not automatically converted into current invoices. |
| `wallet-keygen`, `init` | Browser login with `auth login`, or supply an existing wallet keypair to `auth login --wallet FILE` |

`profile` now manages local named profiles: `create`, `list`, and `use`. Platform commands are grouped under `account`, `org`, `credentials`, `billing`, `payments`, `usage`, `pricing`, `storage`, `compute`, `hosting`, `kv`, and `durable`; `auth`, `context`, and `doctor` handle access and diagnostics. `api list`, `api describe OPERATION_ID`, and `api call OPERATION_ID` expose eligible advanced reads. They do not replace managed payment workflows.

The familiar shortcuts `login`, `logout`, and `whoami` map to the corresponding
authentication/context workflows. `auth status` reports local session metadata
without exposing tokens. `profile show` and `profile set` inspect and update the
selected profile; `profile get` and `profile update` are aliases.

Existing storage spellings remain available: `bucket`, `object`, and `s3` also work under `storage`. `upload-file FILE BUCKET/KEY` and `download-file BUCKET/KEY FILE` retain object put/get behavior. `upload-directory`, `download-directory`, and `sync` remain top-level commands; for example, `pipe sync ./local s3://my-bucket/prefix`. Object downloads require a destination. Encryption passwords use `--password-file FILE` or a terminal prompt. Existing `PIPEENC2` ciphertext remains supported; unsupported historical encryption formats are not converted.

S3 compatibility spellings are also available: `s3 ls`, `s3 cp`, `s3 sync`,
`s3 rm`, `s3 mb`, `s3 rb`, and `s3 head`/`s3 stat`. Recursive copy and removal
are explicit with `--recursive`; removal retains the normal confirmation and
unknown-outcome handling. `s3 ls` without a location checks the configured
profile bucket. Global `ListBuckets` enumeration is not part of the customer
gateway contract; use `s3 ls s3://BUCKET/PREFIX` for object listing.

Storage onboarding is guided: `s3 ls`, `s3 head`, and object-list reads offer to
create a temporary read/list credential when the selected profile has no local
S3 key. The secret is stored in the OS keyring and the original read is retried
once. Uploads and destructive operations never create write credentials
silently; use `pipe s3 setup --write --bucket BUCKET`. `pipe storage init` is an
alias for the setup workflow. With `--no-input`, the CLI reports the exact setup
command. `pipe doctor` includes local endpoint and credential availability in
its diagnostic result.

Existing named profiles retain their explicit endpoints. Ordinary command configuration resolves `--control-api-url`, `PIPE_CONTROL_API_URL`, the selected profile, then `https://api.pipedev.network/control-api`. Storage discovers its customer endpoint; the documented default is `https://gw-001.pipedev.network`. Use `--profile NAME` or `profile use NAME`; `--config FILE` / `PIPE_CLI_CONFIG` select the configuration file. Context changes never transfer ownership or combine infrastructure and platform billing balances.

For a legacy flat configuration, use a separate destination:

```sh
pipe --config /private/pipe-v3.json config migrate --legacy-path /private/pipe-v1.json
pipe --config /private/pipe-v3.json config show
```

Import creates a private backup and copies compatible `control_api_url`, `s3_endpoint`, `bucket`, and `prefix` fields. It does not import website JWTs or `user_app_key`. The old `api_base_url`, `s3_region`, and virtual-hosted-style fields are not imported: select a supported control API and recreate endpoint/region settings explicitly where needed. Existing named profiles do not need this flat-file import.

Authenticate again using `auth login` or `auth login --no-browser` for a printed URL/code. Approval is explicit in the browser. Wallet login uses generalized platform authentication; the preserved storage-only endpoints require the explicit combination `auth login --wallet FILE --legacy-wallet` and compatible server support. There is no automatic legacy fallback. Request additional permissions with `--scope`; session listing/revocation requires `credentials.read`/`credentials.write` respectively. For automation, use an activated scoped credential through `PIPE_CLI_TOKEN`, not a website token or product key.

New secrets use the OS keyring when it is available. On an interactive Linux or headless terminal, login and credential import prompt once to create or unlock the encrypted fallback; the password is held only for that process. For CI and other noninteractive use, set `PIPE_DISABLE_KEYRING=1` and supply `PIPE_CLI_SECRET_PASSWORD` of at least 12 characters through your secret manager. A legacy plaintext fallback remains readable; its next secret update writes encrypted storage and creates a private backup first. Merely setting the password does not rewrite it. Protect that backup, which can contain the original plaintext secrets. Keyring failures never authorize new plaintext storage; secret export requires `--show-secret`.

```sh
pipe config backup /private/pipe-config-backup.json
pipe config rollback /private/pipe-config-backup.json --yes
```

Rollback validates the backup and saves the current configuration before restoring settings. It never rewinds secrets, refresh state, payments, multipart journals, transfer recovery, or ciphertext spools. Preserve the state directory and its secret store, including any explicitly selected `PIPE_CLI_STATE_DIR`. Resume an uncertain operation with its original saved ID and product workflow; reinstalling an older binary or reauthenticating does not resolve its outcome.

For scripts, prefer `--output json`: each result is `{"schema_version":1,"result":...}`. `--output jsonl` emits compact documents and streams pages/events where supported. The retained `--json` flag emits the older unwrapped payload; it cannot be combined with `--output`. Diagnostics and parser errors go to stderr. Use `--no-input` to forbid prompts, supply required input files, and add `--yes` explicitly for commands requiring confirmation. These flags do not grant permissions or imply a completed payment.

Exit statuses are `0` success, `1` other/application failure, `2` command-line syntax, `3` authentication, `4` authorization, `5` unavailable/rate-limited, `6` conflict/precondition, `7` transport, `8` unknown outcome or expired retained response, and `9` wait deadline. SSH propagates the OpenSSH exit status. A wait deadline does not cancel server work; exit `8` requires recovery or reconciliation before submitting another mutation.

## Managed storage workspaces

Existing S3 namespaces and encrypted objects retain their names and owners.
`pipe storage buckets create` returns a durable bucket UUID and its unique S3
name. Use that returned name with `pipe s3 setup --write --bucket NAME` and
ordinary S3 transfers; management commands use the UUID. Creating a bucket label
does not claim or rename a historical namespace.

`pipe storage` now exposes indexed search, scoped keys, CORS, webhooks, lifecycle
previews, activity, and recovery requests. A lost creation response must be
reconciled with `pipe storage requests` and `pipe storage resume REQUEST_ID`.
These encrypted records survive logout. They contain the original request ID;
creating a replacement request can create a second resource.

See [bucket automation](../storage-bucket-automation.md) for complete examples.
Object limits remain negotiated from the deployed gateway; this release retains
the qualified 18 GiB production maximum.
