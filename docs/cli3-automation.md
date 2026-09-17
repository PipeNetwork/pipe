# Scoped automation credentials

Automation credentials are distinct from account API keys, S3 keys, KV keys and deployment keys. They authenticate supported control-plane operations using `PIPE_CLI_TOKEN`. They never become a browser session, BFF token, product key or wallet signing key.

Log in interactively with the permissions you intend to delegate plus `credentials.write`. Inspect `pipe context` for the exact `owner_wallet` and canonical `account_id`. Supply `--account-context ACCOUNT_ID` when the identity has a canonical account; omit it for an infrastructure-only identity.

Choose the authority explicitly:

```sh
# Operate only on this existing VM.
pipe credentials create --label deploy \
  --owner-wallet OWNER --account-context ACCOUNT_ID \
  --scope "compute.read compute.write" \
  --resource compute_vm:VM_UUID --expires-in 3600

# Inspect only the selected organization.
pipe credentials create --label org-reports \
  --owner-wallet OWNER --account-context ACCOUNT_ID \
  --scope "org.read billing.read" --organization ORG_ID

# Explicit account-wide product access includes future owned resources.
pipe credentials create --label account-reports \
  --owner-wallet OWNER --account-context ACCOUNT_ID \
  --scope "compute.read kv.read" --account-access
```

`--resource` accepts `compute_vm`, `kv_instance`, `durable_namespace` and `hosting_site`, each followed by a colon and UUID. Repeat the option to select multiple resources (at most 32). Resource grants restrict lists, reads and mutations to those resources, including their existing objects, releases or operations. Lists filter before pagination. Resource-only grants cannot create replacement resources or read whole-account balances, credentials or hosting billing. Grant `billing.write` separately for supported resource spending-limit or renewal settings. Provisioning new resources requires explicit account access.

Repeat `--organization` for up to 32 memberships. Organization scopes always require selected organizations, including with `--account-access`. Lists include only selected organizations. Current role permissions still apply. The server checks the membership revision on every use; removal, rejoining, promotion or demotion requires issuing a fresh credential. Organization creation and invitation acceptance require an interactive session.

Listing CLI sessions requires `credentials.read`; revoking a named CLI session requires `credentials.write`. Self logout remains available with any interactive session grant.

The issuer's scopes and remaining session lifetime limit every grant. Expiry is 60 seconds to 30 days, capped by the issuer session's expiry. Logout, issuer-session revocation, identity revocation or changed account links invalidate the affected credentials. Automation cannot delegate `credentials.write`, issue broad account/product keys or perform hosted billing and settlement workflows that require an interactive session.

The CLI saves new secrets and grant metadata to the OS keyring or explicitly selected encrypted fallback before activation. A lost activation response can be reconciled using the same material:

```sh
pipe credentials activate CREDENTIAL_UUID
pipe credentials list
pipe credentials export CREDENTIAL_UUID
pipe credentials export CREDENTIAL_UUID --show-secret --output json
pipe credentials revoke CREDENTIAL_UUID --yes
```

Export checks that the saved credential remains active and has the same identity. Secrets appear only with `--show-secret`; ordinary output and listings redact them. A failed creation response never activates an unknown secret. Inspect the credential list and revoke unused inactive records before creating a replacement.

The additive optional CLI schema v3 preserves existing account-bound credentials and secrets. Preserved credentials gain no organization authority. New resource/organization grants require compatible v3 backend support; feature availability remains governed by deployment admission and the existing product launch gates.
