# Billing and hosted payments

Infrastructure credit and platform billing credit remain separate balances. Card top-ups under `billing card` fund the selected linked infrastructure wallet in integer USD cents. Organization checkout funds platform billing credits, where one credit is USD 0.04. Selecting an organization does not move balances.

```sh
pipe billing card config
pipe billing card list
pipe billing card checkout --wallet WALLET --amount-cents 999 --yes
pipe billing card reconcile ORDER_ID --yes

pipe billing checkout ORG_ID --amount-cents 501 --yes
pipe billing plan-checkout ORG_ID --plan code --yes
pipe billing portal ORG_ID --yes
pipe billing settings ORG_ID --enabled false --yes
```

Checkout and portal commands return a validated HTTPS Stripe URL. Open that URL to complete the browser workflow. Creating a checkout never submits a card payment. Checkout redirects return to the existing billing page on `pipe.network`. The CLI never receives browser cookies, website session tokens, BFF credentials or card details.

Billing changes require an interactive CLI session and `billing.write`. Organization changes also require `org.read` and current organization billing permissions. Scoped automation can inspect permitted billing records; it cannot create hosted sessions, change automatic recharge, or settle/reconcile a payment. All mutation commands require interactive confirmation or `--yes`.

`--amount-cents` and `--threshold-cents` take whole USD cents. To enable automatic recharge, explicitly supply `--enabled true`, a positive threshold, and a purchase amount of 500–1000000 cents at least equal to the threshold. Enabling recharge authorizes subsequent automatic charges by the existing billing service. Use `pipe billing get ORG_ID` to inspect current settings and subscriptions.

Before sending any billing mutation, the CLI saves the exact request, identity context and request UUID in its encrypted billing journal. It uses the OS keyring or the explicitly configured encrypted secret fallback. Failure to save prevents submission. Payment and transfer journals from earlier versions remain intact.

```sh
pipe billing requests
pipe billing resume REQUEST_ID --yes
```

A timeout, conflicting receipt, or lost response reports exit status 8 and keeps the original request. Another billing mutation cannot replace an unresolved request. Explicit resume reuses the original hosted request UUID, amount, URLs, invoice identifier, reference and verification signature. Hosted Stripe requests are also persisted by the server before contacting Stripe. Recorded results remain recoverable; an unrecorded provider result can be retried with its original key only during the 23-hour safety window. After that window the request remains unresolved for support reconciliation, and the server prevents a replacement checkout. This limit leaves a margin before Stripe can discard idempotency records at 24 hours; all Stripe POST endpoints support such keys. [Stripe idempotency contract](https://docs.stripe.com/api/idempotent_requests).

Automatic-recharge settings are never replayed after an unknown outcome. Resume observes current settings and completes only when they match the saved request. A different current value remains unknown; no later configuration is overwritten.

The retained Solana Pay workflow is labeled legacy and creation remains unavailable until the deployment explicitly enables it:

```sh
pipe billing solana create ORG_ID --amount-cents 500 --yes
pipe billing solana verify ORG_ID PAYMENT_ID --signature SIGNATURE --yes
pipe billing solana sync ORG_ID PAYMENT_ID --yes
```

Creation saves its original payment ID and 32-byte reference before submission and validates the returned recipient, mint, amount and payment URL. These commands do not sign or broadcast transactions. Verification accepts the signature of a transaction already submitted outside this workflow. The server checks finalized transaction ownership, reference, amount, mint and validity window before applying the original credit fence. Repeated verification or synchronization cannot duplicate that credit. Existing invoices remain reconcilable when creation is disabled.

The billing fixture uses disposable PostgreSQL, the executable CLI with explicit simulated browser approval, and local Stripe/Solana provider sandboxes. It validates lost responses, identical provider idempotency, stale-request limits, scope and membership changes, and duplicate-credit prevention. It does not establish production Stripe or Solana settlement or real browser qualification.
