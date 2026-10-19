// examples/vulnerable/client/payment.ts
//
// DELIBERATELY WRONG. This file exists so a reader can run the scanner and see
// the documented anti-patterns matched. It uses no real keys, no real users,
// and no personal data. Do not copy anything from this file.

// PSC-009: Pi SDK used; no visible Pi.init() in this file.
const { user, accessToken } = await window.Pi.authenticate(["username", "payments"], onIncompletePayment);

// PSC-002: the client user object is trusted and stored, with no accessToken
// verification anywhere in this file.
localStorage.setItem("piUser", JSON.stringify(user));
if (user.uid) showPremiumNav();

// PSC-001: the Server API Key is used from client code.
async function approve(paymentId) {
  return fetch("https://api.minepi.com/v2/payments/" + paymentId + "/approve", {
    method: "POST",
    headers: { Authorization: "Key " + PI_API_KEY },
  });
}

// PSC-003: the feature is granted before server-side completion.
window.Pi.createPayment(
  { amount: 1, memo: "Premium", metadata: {} },
  {
    onReadyForServerApproval: (paymentId) => approve(paymentId),
    onReadyForServerCompletion: (paymentId, txid) => complete(paymentId, txid),
  }
);
setIsPremium(true);

// PSC-005: a user-specific call with no Authorization header.
async function claimReward(adId) {
  return fetch("/api/ads/reward", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ adId }),
  });
}

// PSC-006: the reward is granted on the client ad result alone.
async function watchAd() {
  const result = await window.Pi.Ads.showAd("rewarded");
  if (result.result === "AD_REWARDED") {
    addExtraLife();
  }
}

// PSC-007: the token is read from a non-public internal property.
const internalToken = window.PiSdkBase?.accessToken ?? "";

// PSC-008: completion is called with empty values.
async function complete(paymentId, txid) {
  return fetch("/api/payment/complete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ paymentId: "", txid: "" }),
  });
}
