# Captured fixtures

Real bytes captured from Clio Manage on 2026-08-20 by a deployed receiver at
`clio-matter-bridge.vercel.app`, logged verbatim. These are the ground truth the
library is written against, in preference to any documentation.

- `clio-handshake.json` — body of the activation handshake. Arrives with header
  `x-hook-secret: <uuid>`, which must be echoed back with a 200 to move the
  subscription from `pending` to `enabled`.
- `clio-delivery-created.json`, `clio-delivery-updated.json` — real deliveries.
  Arrive with header `x-hook-signature: <hex>`, an HMAC-SHA256 of the RAW body
  keyed on the handshake secret. Verified matching.

What these disproved, all of which the library originally assumed wrongly:

1. The event name is at `meta.event`, NOT top level, and there is no `model`
   field in the payload at all (model belongs to the subscription).
2. There is NO timestamp anywhere in the payload, so a replay guard that
   requires one rejects every genuine delivery.
3. There is no dedicated event id. `data.etag` changes between versions of the
   same record, so `id` plus `etag` is the usable idempotency key.

Subscriptions also carry `expires_at` roughly 3 days out and must be renewed.
