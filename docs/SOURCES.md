# Sources

Every rule cites one of the official pages below. Nothing in this repository is
based on an unofficial source, and no rule is based on an opinion.

---

## S1 — Common Pi SDK Integration Mistakes  ·  `documented`

<https://docs.minepi.com/troubleshooting/CommonMistakes>

Pi's own troubleshooting page, documenting **eight numbered mistakes** (Mistake
1 → Mistake 8) with `Wrong` and `Correct` examples. This is the primary rule
source: PSC-002 through PSC-009 each map to one numbered mistake.

| Official mistake | Rule |
|---|---|
| Mistake 1 — Missing `pi-sdk.js` / `Pi.init()` | PSC-009 |
| Mistake 2 — Never sending `accessToken` to the backend | PSC-002 |
| Mistake 3 — Granting features before server completion | PSC-003 |
| Mistake 4 — Payment callback path mismatch | PSC-004 |
| Mistake 5 — Not sending auth headers | PSC-005 |
| Mistake 6 — Not verifying rewarded ads server-side | PSC-006 |
| Mistake 7 — Reading `accessToken` from internal properties | PSC-007 |
| Mistake 8 — Calling completion with empty `paymentId`/`txid` | PSC-008 |

## S2 — Platform API Reference  ·  `documented`

<https://docs.minepi.com/api-reference/PlatformAPI>

States the Server API Key rule verbatim: *"Your Server API Key **must** be kept
on your server, and must not be sent to clients … Letting users access your
server API key is a **serious security breach**."* This is the anchor for
PSC-001. Also documents `/me`, `/payments/{id}/approve`, `/payments/{id}/complete`
and `/ads_network/status/:adId`.

## S3 — Pi Network Authentication Guide  ·  `documented`

<https://docs.minepi.com/authenticate-user/Authentication>

Documents `Pi.init`, `Pi.authenticate`, the backend `/me` verification flow, and
the advice to request the narrowest scopes. Supports PSC-002, PSC-009.

## S4 — Client SDK Reference  ·  `documented`

<https://docs.minepi.com/api-reference/SdkReference>

The low-level reference for `window.Pi`: authentication, payments, ads, wallet
and native features. Supports the method names the rules match against.

---

## What is **not** a source here

- **No third-party blog posts or forum answers** are used as a basis for any rule.
- **No "general security best practices"** list is used. Every rule is Pi-specific
  and quoted from the pages above.
- **No CVE or advisory database.** The scanner has no network and consults none.

## Claim kinds

| Kind | Meaning |
|---|---|
| `documented` | quoted from Pi's official documentation; the quote and URL are stored with the rule |
| `derived` | a mechanical consequence of a documented rule, recorded as derived (PSC-004 is the only one) |
| `not-claimed` | out of scope: overall security, exploitability, runtime behaviour |

## Reproduce

```bash
node scan-cli.mjs --sources    # this list, offline
node scan-cli.mjs --rules      # each rule with its quote and URL
```
