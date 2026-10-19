# Rules

Every rule is anchored to a **verbatim quote** from Pi's official documentation.
A rule that could not be tied to such a quote would not be a rule here.

The primary source is **Common Pi SDK Integration Mistakes** (eight numbered
mistakes). One rule (PSC-001) comes from the **Platform API** page's Server API
Key warning.

---

## PSC-001 — Server API Key present in client-reachable code

**Severity:** high · **Claim kind:** documented

**Official quote** (Platform API Reference):

> Your Server API Key **must** be kept on your server, and must not be sent to
> clients (do not use it in your client JavaScript code). In the future, your
> server API key might enable sensitive operations on your app itself that your
> users should not be allowed to perform. Letting users access your server API
> key is a **serious security breach**.

**Source:** <https://docs.minepi.com/api-reference/PlatformAPI>

**Matches:** an `Authorization: Key …` header, or a key-shaped literal assigned
to a `piApiKey` / `serverApiKey` name, in a file classified as **client**.

**Wrong / correct:**

```js
// wrong — this runs in the browser
headers: { Authorization: 'Key ' + PI_API_KEY }

// correct — the approve/complete calls happen on your server, where the key lives
```

---

## PSC-002 — Client user object trusted as identity without server verification

**Severity:** high · **Claim kind:** documented

**Official quote** (Mistake 2):

> This is a security flaw: the frontend `user` object can be spoofed. The
> **only** trusted source of user identity is the Pi Platform API's `/me`
> endpoint, which validates the `accessToken` server-side.

**Source:** <https://docs.minepi.com/troubleshooting/CommonMistakes>

**Matches:** the client `user` is stored or used to authorise, **and** the file
contains no reference to sending the `accessToken` for verification (`/me`, an
`auth/verify` route, or a `Bearer` header with the token).

**Wrong / correct:**

```js
// wrong — trusted locally, never verified
localStorage.setItem('piUser', JSON.stringify(user));

// correct — POST the accessToken; the backend calls GET /v2/me with Bearer <accessToken>
```

---

## PSC-003 — Feature granted before server-side completion

**Severity:** high · **Claim kind:** documented

**Official quote** (Mistake 3):

> **Server Completion** (`onReadyForServerCompletion`) — your server confirms
> completion and **delivers the feature**. A common mistake is granting the
> feature (e.g., premium mode, extra lives) at Phase 1 or when the payment modal
> closes, rather than waiting for Phase 3 to complete successfully on the server.

**Source:** <https://docs.minepi.com/troubleshooting/CommonMistakes>

**Matches:** a grant-like call (`setIsPremium`, `addExtraLife`, `grantReward`, …)
that sits **inside a `createPayment` call region but outside** the
`onReadyForServerCompletion` callback body. The rule only applies when the file
contains a payment flow, so an unrelated reward call is not caught here.

**Wrong / correct:**

```js
// wrong — granted as soon as the flow starts
window.Pi.createPayment({...}, {...});
setIsPremium(true);

// correct — granted only after the backend confirms completion
onReadyForServerCompletion: async (paymentId, txid) => {
  const res = await fetch('/api/payments/complete', {...});
  if (res.ok) setIsPremium(true);
}
```

**Detection note:** callback-body detection is a brace heuristic. Where the
completion handler is a bare function reference with no inline body, any grant in
the payment region is treated as outside it, and that is reported plainly.

---

## PSC-004 — Payment callback path worth cross-checking

**Severity:** low · **Claim kind:** **derived**

**Official quote** (Mistake 4):

> `Pi.createPayment()` callbacks must POST `paymentId` / `txid` to **your**
> backend routes. If the frontend calls a path your server does not expose, the
> request returns 404 and the payment stalls in approval or completion.

**Source:** <https://docs.minepi.com/troubleshooting/CommonMistakes>

**Matches:** a line declaring `onReadyForServerApproval` / `onReadyForServerCompletion`
alongside an `approve`/`complete` path.

**Why this is `derived`, not `documented`:** the scanner cannot see your server,
so it cannot detect a real mismatch. It can only flag that the callback paths
exist and should be cross-checked. Severity is **low** for that reason. This is
the honest form of a check a static scanner cannot fully make.

---

## PSC-005 — Authenticated backend call without an Authorization header

**Severity:** medium · **Claim kind:** documented

**Official quote** (Mistake 5):

> Backend endpoints that perform user-specific actions (granting rewards,
> updating scores, delivering purchased features) need to know **which user** is
> making the request. If your backend uses token-based auth … forgetting to
> include the header means `current_user` is `nil` and the user-specific
> operation silently does nothing.

**Source:** <https://docs.minepi.com/troubleshooting/CommonMistakes>

**Matches:** a `fetch(...)` to a user-specific route (`reward`, `grant`, `profile`,
`score`, `purchase`, `unlock`, …) in a statement that carries **no**
`Authorization` header.

**Wrong / correct:**

```js
// wrong
fetch('/api/ads/reward', { method: 'POST', body: JSON.stringify({ adId }) });

// correct
fetch('/api/ads/reward', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
  body: JSON.stringify({ adId }),
});
```

---

## PSC-006 — Rewarded-ad reward granted without server-side verification

**Severity:** high · **Claim kind:** documented

**Official quote** (Mistake 6):

> After `Pi.Ads.showAd('rewarded')` resolves with `{ result: 'AD_REWARDED', adId }`,
> some apps grant the reward immediately based on the client-side result. The Pi
> SDK client response **can be spoofed**. The `adId` **must always** be verified
> against the Pi Platform API before granting any reward.

**Source:** <https://docs.minepi.com/troubleshooting/CommonMistakes>

**Matches:** an `AD_REWARDED` check that grants a reward, in a file that shows
**no** ad verification (a call to `ads_network/status`, a `mediator_ack_status`
check, or a backend reward call whose response gates the grant).

**Wrong / correct:**

```js
// wrong
if (result.result === 'AD_REWARDED') addExtraLife();

// correct — verify server-side first
if (result.result === 'AD_REWARDED' && result.adId) {
  const res = await fetch('/api/ads/reward', {...});
  const data = await res.json();
  if (data.rewarded) addExtraLife();
}
```

---

## PSC-007 — `accessToken` read from a non-public internal property

**Severity:** medium · **Claim kind:** documented

**Official quote** (Mistake 7):

> Some implementations try to read the token from undocumented properties such as
> `window.PiSdkBase?.accessToken`. Those properties are **not part of the public
> Pi SDK API**, are not guaranteed to exist, and typically return `undefined` or
> an empty string.

**Source:** <https://docs.minepi.com/troubleshooting/CommonMistakes>

**Matches:** `window.PiSdkBase?.accessToken`, `window.PiSdkBase.accessToken`, or
`window.Pi?._accessToken`.

**Wrong / correct:**

```js
// wrong
const accessToken = window.PiSdkBase?.accessToken ?? '';

// correct
const { user, accessToken } = await window.Pi.authenticate([...], onIncompletePayment);
```

---

## PSC-008 — Completion called with empty/fabricated `paymentId` / `txid`

**Severity:** medium · **Claim kind:** documented

**Official quote** (Mistake 8):

> `onReadyForServerCompletion` is the only client callback that provides the real
> `paymentId` and `txid`. Completing a payment with empty or fabricated values
> causes the Platform API to reject the request … The client may **look finished**
> while the server never confirmed the payment with Pi.

**Source:** <https://docs.minepi.com/troubleshooting/CommonMistakes>

**Matches:** `paymentId: ''`, `txid: ''`, `paymentId: null`, `txid: undefined`.

**Wrong / correct:**

```js
// wrong
body: JSON.stringify({ paymentId: '', txid: '' })

// correct
body: JSON.stringify({ paymentId, txid })
```

---

## PSC-009 — Pi SDK used with no visible `Pi.init()` call

**Severity:** low · **Claim kind:** documented

**Official quote** (Mistake 1):

> `Pi.init()` **must** be called before any other Pi SDK calls … Calling Pi SDK
> methods without `Pi.init()` first … **ERROR: `Pi.init()` was never called**.

**Source:** <https://docs.minepi.com/troubleshooting/CommonMistakes>

**Matches:** `window.Pi.authenticate(...)` or `window.Pi.createPayment(...)` in a
file that contains no `Pi.init(`.

**Why severity is low:** `Pi.init()` may legitimately live in another file (an
app entry point). A static per-file scan cannot see that, so this is a
**prompt**, not a verdict.

**Wrong / correct:**

```js
// wrong (in this file)
window.Pi.authenticate(['username'], onIncompletePaymentFound);

// correct
Pi.init({ version: '2.0', sandbox: false });
```

---

## Reproduce

```bash
node scan-cli.mjs --rules                   # this page's content, offline
node scan-cli.mjs --scan examples/vulnerable  # every rule fires
node scan-cli.mjs --scan examples/corrected   # zero findings
node test/run.mjs                           # the invariants above, asserted
```
