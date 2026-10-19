// examples/corrected/client/payment.ts
//
// The CORRECTED form of the file next to it, following the documented patterns:
// each change below corresponds to the rule it satisfies. It contains no real
// keys, no real users, and no personal data.

// PSC-009 satisfied: Pi.init() is called before any other Pi SDK method.
window.Pi.init({ version: "2.0", sandbox: false });

// PSC-002 satisfied: the client user object is NOT trusted; the accessToken is
// sent to the backend, which verifies it against GET /v2/me.
export async function login() {
  const { user, accessToken } = await window.Pi.authenticate(
    ["username", "payments"],
    onIncompletePayment
  );
  const res = await fetch("/api/auth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ accessToken }),
  });
  const verified = await res.json();
  return { uid: verified.uid, username: verified.username, accessToken };
}

// PSC-003 satisfied: the feature is granted ONLY after the backend confirms
// completion.
export function buyPremium(accessToken) {
  window.Pi.createPayment(
    { amount: 1, memo: "Unlock Premium", metadata: { feature: "premium" } },
    {
      onReadyForServerApproval: async (paymentId) => {
        await fetch("/api/payments/approve", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
          body: JSON.stringify({ paymentId }),
        });
      },
      onReadyForServerCompletion: async (paymentId, txid) => {
        // PSC-008 satisfied: the real (paymentId, txid) are sent.
        const res = await fetch("/api/payments/complete", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
          body: JSON.stringify({ paymentId, txid }),
        });
        if (res.ok) {
          // Only here, after the server confirms, is the feature delivered.
          setIsPremium(true);
        }
      },
      onCancel: (paymentId) => console.log("cancelled", paymentId),
      onError: (error) => console.error("payment error", error),
    }
  );
}

// PSC-005 satisfied: the user-specific call carries the Authorization header.
export async function claimReward(adId, accessToken) {
  return fetch("/api/ads/reward", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ adId }),
  });
}

// PSC-006 satisfied: the reward is granted only after server-side verification.
export async function watchAd(accessToken) {
  const result = await window.Pi.Ads.showAd("rewarded");
  if (result.result === "AD_REWARDED" && result.adId) {
    const res = await fetch("/api/ads/reward", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ adId: result.adId }),
    });
    const data = await res.json();
    if (data.rewarded) {
      addExtraLife();
    }
  }
}
