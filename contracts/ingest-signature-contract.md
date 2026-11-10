# SDK request signature contract (version 2)

Applies to **every** SDK-to-platform call: event ingest, license check,
heartbeat, blocked-status, action confirmation, test IPs, telemetry rollup, ML
classification and the rest. Every SDK, in any language, must sign each request
this way. (The file keeps its original `ingest-signature-*` name so existing
links and vector consumers do not move.)

Acceptance test: pass every vector in
[`ingest-signature-vectors.json`](./ingest-signature-vectors.json). The Node and
Python SDKs, the platform and the open-core ingest route all assert that same
file. The vectors are produced by
[`generate-ingest-signature-vectors.py`](./generate-ingest-signature-vectors.py),
plain `hashlib`/`hmac`, independent of every SDK and of the platform.

## Version

This is signature version **2**, sent as `X-DevFortress-Signature-Version: 2`.
Version 1 (which did not cover the method or path) was never published and has
no customers, so it was replaced outright: there is no v1 support. On the
key-ID path a missing or unknown version is `401` with
`reason: signature_version_unsupported`.

## Signed string

```
{METHOD}.{request_target}.{timestamp}.{nonce}.{payload_hash}
```

- `METHOD`: the uppercase HTTP method (`GET`, `POST`, ...).
- `request_target`: the URL path plus `?` plus the query string, exactly as sent
  on the request line. No scheme or host, no re-encoding, no normalisation, and
  no trailing `?` added or removed. A path prefix the client used (for example a
  gateway prefix) is part of the target.
- `payload_hash`: lowercase hex SHA-256 of the exact request body bytes (UTF-8),
  the same bytes sent on the wire. A request with no body hashes the empty
  string (`e3b0c442...b855`). Do not re-serialise after hashing.
- `signature`: lowercase hex HMAC-SHA256 of the signed string (UTF-8), keyed
  with the project API key (UTF-8, the `vx_live_...` key).

Signing the method and target means a captured signature cannot be replayed on
another endpoint, with another method, or with a changed query, even when both
requests have an empty body.

## Key ID

The API key never travels on a signed request. Instead the client sends a
non-secret key ID derived from the key:

```
key_id = first 32 lowercase hex characters of SHA-256(UTF-8 API key)
```

Customers configure nothing new. Keys are high-entropy random values, so the
hash prefix reveals nothing usable. The platform stores the key ID (unique,
indexed) and looks the project up by it, then verifies the HMAC with the key it
has stored. Derivation vectors are under `key_id_derivation` in the vectors
file.

The API key must not appear in any header, query string or body of any SDK
request: not `X-DevFortress-Key`, not `X-API-Key`, not `Authorization`, and not
an `api_key` body field.

## Headers

| Header                            | Value                                   |
| --------------------------------- | --------------------------------------- |
| `X-DevFortress-Key-Id`            | `key_id` above                          |
| `X-DevFortress-Signature-Version` | `2`                                     |
| `X-DevFortress-Nonce`             | Dashed UUID v4, at most 128 characters  |
| `X-DevFortress-Timestamp`         | Unix epoch milliseconds, decimal string |
| `X-DevFortress-Payload-Hash`      | `payload_hash` above                    |
| `X-DevFortress-Signature`         | `signature` above                       |

All six are required together on the signed path, on every method including
`GET`. Hex is compared case-insensitively.

## Tolerance and nonce

- Timestamp tolerance: 300 seconds either side of server time. Outside it the
  server answers `400` with `reason: timestamp_expired`.
- A nonce is accepted once per project within the tolerance window, across all
  signed routes (one store, not one per route). A repeat is `409` with
  `reason: nonce_replayed`.

## Retry rule

Every attempt, including retries after a 5xx or network error, must use a new
nonce and a new timestamp and be signed again. Reusing a nonce makes the retry
look like a replay.

## Server behaviour: two auth paths on every SDK-facing route

**Signed path** (`X-DevFortress-Key-Id` present). The platform finds the project
by key ID, verifies the HMAC with the stored key (constant-time compare) over
the method and request target it received, then checks timestamp tolerance,
then nonce replay (per project). The signature is the authentication, so a
missing or invalid signature is `401` (`reason: signature_missing`,
`signature_invalid` or `signature_version_unsupported`) whether or not the
enforcement flag is on. An unknown key ID gets the same `401` shape as a bad
signature, so responses do not reveal which key IDs exist.

**Legacy path** (API key in a header or body, no key ID). Unchanged:

- Enforcement flag off (default): requests are accepted, including unsigned
  ones from older clients; the outcome (`valid`, `invalid`, `missing`) is only
  logged. Replay rejection behaves as it always has.
- Enforcement flag on: a missing or invalid signature is `401` with
  `reason: signature_missing`, `signature_invalid` or
  `signature_version_unsupported`. Replay rejection runs only after the
  signature has been verified.

**Both** a key ID and any API-key carrier present: `400` with
`reason: ambiguous_credentials`.

The browser build of the Node SDK stays on the legacy path.

Shared vectors: `signed_path_vectors` and `legacy_path_vectors` give the
expected status and reason for each case.

## Reconstructing the request target on the server

The platform takes the target from the request URL the runtime reports (path
plus query, after the authority) and never normalises it. If something in front
of the platform rewrites the path or query (for example a reverse proxy that
strips a prefix), the bytes the platform sees differ from the bytes the client
signed and the request is rejected as `signature_invalid`. Point the SDK
`endpoint` at the URL the platform itself serves, or configure the proxy to pass
the path through unchanged.

## Verifier results used by the vectors

`valid`, `invalid` (headers present, mismatch), `expired` (correct signature,
timestamp outside tolerance), `missing` (a required header is absent),
`unsupported_version` (version header absent or not `2`).

## Adding a language

1. Implement key ID derivation and signing; pass `key_id_derivation` and every
   `sign_input` vector byte-for-byte.
2. Implement a verifier (constant-time compare) and pass every `expected`.
3. Sign **every** platform call (not only ingest): the key must not appear on
   the wire at all.
4. Send a fresh nonce and timestamp per attempt; test it with a stub server
   that fails once, and with a stub that records every request of a scripted
   lifecycle and asserts the key appears nowhere.
