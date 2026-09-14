# Stripe subscriptions and account access

Implementation status: development integration. No Stripe account, Price, checkout, subscription, refund or payment has been created by this work. An operationally approved deployment and actual Stripe test-mode acceptance remain required.

The authenticated Relayne team server owns billing. Desktop users enter their existing team server origin and token under Account and subscription. Each authenticated actor has one billing customer and at most one currently bound single-user subscription. Terminal canceled or incomplete-expired subscriptions are retired permanently so the account can subscribe again; delayed events for retired subscriptions cannot replace the new binding. Client input cannot select another customer, arbitrary Price or quantity. Team bearer tokens remain in memory; Stripe secrets are server environment variables only.

## Server configuration

Use a TLS reverse proxy for the existing team server. Configure these environment variables in its protected service environment, never in desktop settings or a distributed package:

- `RELAYNE_STRIPE_SECRET_KEY`: a restricted deployment credential with the required Customer, Checkout, Billing Portal, Price and Subscription permissions. Restricted `rk_test_` / `rk_live_` keys are recommended with only the listed permissions; standard `sk_test_` / `sk_live_` keys are also accepted.
- `RELAYNE_STRIPE_WEBHOOK_SECRET`: the `whsec_` signing secret for this endpoint.
- `RELAYNE_STRIPE_PRICE_ID`: an active recurring licensed Price. Explicit inclusive/exclusive tax behavior is required. The proposed EUR 9.99 amount and tax treatment have not been approved; the configured Stripe Price is authoritative.
- `RELAYNE_STRIPE_RETURN_URL`: the seller-controlled HTTPS account page for checkout and portal return.
- `RELAYNE_COMMERCE_APPROVED=true`: additionally required for live keys, after legal, pricing, support and operational approval. Setting this flag does not constitute that approval.

Enable Stripe Tax as required for the seller's registrations and configure the Stripe Customer Portal with the approved cancellation, invoice and payment-method options. Register `POST /v1/billing/webhook` for `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`, and `invoice.payment_failed`. Keep test and live keys, databases and webhook endpoints separate. The client pins the Stripe API version to `2025-03-31.basil`; validate provider responses before upgrading it.

## Checkout, activation and cancellation

`POST /v1/billing/checkout` receives a UUID `attempt`. Retrying an uncertain request must retain that UUID. The server supplies the authenticated customer's identity, exact configured Price and quantity 1 to Stripe Checkout in subscription mode. The desktop displays a Stripe-hosted link for explicit review; it never treats a redirect as proof of payment.

`POST /v1/billing/portal` creates a short-lived Customer Portal session for the authenticated customer. Cancellation and invoice/payment-method management use the portal's approved configuration. Refunds are not automatically decided by Relayne: authorized billing staff handle them in Stripe according to approved terms. Refund-only events are not currently entitlement revocation triggers; cancel the subscription when policy requires access to end.

`GET /v1/billing/entitlement` reads server state; `POST /v1/billing/refresh` explicitly reconciles with Stripe. Activation requires an active subscription, a paid latest invoice, the exact configured Price, quantity 1, an unexpired paid period, and verification less than 24 hours old. Missing, stale, unpaid or mismatched evidence grants no active entitlement. Trials are not enabled by this implementation. The development application remains usable as a development build; this account status does not retroactively license the development release or authorize remote actions.

## Webhook integrity and operations

Verify the signature against the exact raw body before parsing. Requests are bounded to 1 MiB and timestamps to five minutes. The signing mode must match the configured key mode. Event IDs are durable and replay-safe. Relevant subscription events trigger retrieval of the current Stripe subscription, so out-of-order event bodies cannot restore obsolete access. Reconciliation and event recording commit together. A failed reconciliation returns an error for retry and is not recorded as complete.

Keep the team SQLite database backed up under the same operational controls as team identities. Monitor webhook delivery failures in Stripe. Account data includes actor/customer/subscription identifiers, subscription status, paid-period end, verification time and received event IDs. It does not include card details. No autonomous payment retries or bulk billing operations run in the desktop.

## Required acceptance before live use

Use Stripe test mode to exercise initial payment, failure, delayed webhook, replay, cancellation at period end, immediate cancellation, portal invoice access and interrupted checkout retry. Confirm the configured Price/tax behavior, seller registrations, portal policies, payment-method availability and webhook/API schema. Offline tests cover local signature, time, account, Price and entitlement boundaries; they are not a provider acceptance result.

## Checkout recovery and renewal

Before calling Stripe, the server saves an account-scoped checkout intent. An interrupted request reuses that saved attempt even if the desktop supplies another UUID. An existing open Checkout Session is retrieved and reused; a new session can replace it only after Stripe reports it expired and the operator supplies a new attempt. Completed sessions reconcile their canonical subscription and do not create another checkout. An unresolved request older than 23 hours requires billing support because Stripe may expire its idempotency record after 24 hours; the server does not silently retry with another key. Pending attempts and retired subscription IDs must remain in the backed-up database.

Invoice payment success and failure events resolve the subscription using the Basil `parent.subscription_details.subscription` field, with consistent legacy references accepted during migration. The server then retrieves the canonical subscription and expanded latest invoice; an event's own payment claim never grants access. Standalone invoices do not affect subscriptions. Manual verification remains necessary if delivery fails or verification becomes stale. This integration does not run a periodic subscription refresh worker.

Offline lifecycle tests exercise uncertain request retries, open-session reuse, verified expiry before replacement, account mismatch rejection, old-event retirement, invoice reference parsing, and payment-state reconciliation. These tests use in-memory SQLite and injected responses; they do not prove Stripe endpoint acceptance, tax configuration, cancellation UX, or live payment behavior.

Pinned schema reference: [Stripe invoice object, API 2025-03-31.basil](https://docs.stripe.com/api/invoices/object?api-version=2025-03-31.basil), reviewed September 14, 2026. Entitlement uses `status` and explicit `amount_remaining`; it does not rely on the removed invoice `paid` Boolean.
