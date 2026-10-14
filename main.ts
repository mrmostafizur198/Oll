// Deno Deploy — পুশ নোটিফিকেশন সার্ভার (ফ্রি, কার্ড ছাড়া)
// Environment variables:
//   SA_JSON  = Firebase service account JSON (Secret)
//   DB_URL   = https://xxxx-default-rtdb.firebaseio.com   (শেষে / নেই)
//   CLICK_URL   (ঐচ্ছিক) = নোটিফিকেশনে চাপলে যে https লিংক খুলবে (না দিলে অ্যাপের service worker খোলে)
//   ALLOW_ORIGIN (ঐচ্ছিক) = আপনার অ্যাডমিন সাইটের লিংক, যেমন https://admin.example.com
//   NOTIF_NODE  (ঐচ্ছিক) = বার্তার নোড, ডিফল্ট: user_notifications   (গঠন: NOTIF_NODE/{uid}/{nid} = {title, body})
//   USERS_NODE  (ঐচ্ছিক) = ইউজার নোড, ডিফল্ট: users
//   TOKEN_FIELD (ঐচ্ছিক) = ফোন টোকেনের ফিল্ড, ডিফল্ট: fcmToken        (USERS_NODE/{uid}/TOKEN_FIELD)
// অ্যাডমিন অ্যাপ শুধু { uid, nid } পাঠায়। বার্তার লেখা ডাটাবেস থেকেই পড়া হয়,
// তাই বাইরে থেকে কেউ নিজের মতো বার্তা পাঠাতে পারে না, আর একই বার্তা একবারের বেশি যায় না।

const cors = (): Record<string, string> => ({
  "Access-Control-Allow-Origin": Deno.env.get("ALLOW_ORIGIN") || "*",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
});

const b64u = (buf: ArrayBuffer | Uint8Array): string =>
  btoa(String.fromCharCode(...new Uint8Array(buf as ArrayBuffer)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const enc = (s: string): string => b64u(new TextEncoder().encode(s));

// সার্ভিস অ্যাকাউন্ট দিয়ে গুগলের অ্যাক্সেস টোকেন আনা
let cached: { token: string; exp: number } | null = null;
async function accessToken(sa: any): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (cached && cached.exp > now + 60) return cached.token;
  const head = enc(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = enc(JSON.stringify({
    iss: sa.client_email,
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3300,
    scope: "https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email",
  }));
  const pem = String(sa.private_key).replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const key = await crypto.subtle.importKey(
    "pkcs8",
    Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(head + "." + claim)));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + head + "." + claim + "." + sig,
  });
  const j = await r.json();
  cached = { token: j.access_token, exp: now + 3300 };
  return j.access_token;
}

const reply = (text: string, status = 200) => new Response(text, { status, headers: cors() });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors() });
  if (req.method !== "POST") {
    // ব্রাউজারে  লিংক/?status  খুললে কী ঠিক আছে দেখা যায় (গোপন মান দেখায় না, শুধু ok/missing)
    if (new URL(req.url).searchParams.has("status")) {
      let sa = "ok";
      const raw = Deno.env.get("SA_JSON") || "";
      if (!raw) sa = "missing";
      else {
        try { const j = JSON.parse(raw); if (!j.private_key || !j.client_email) sa = "no-private-key"; }
        catch (_e) { sa = "invalid-json"; }
      }
      return new Response(JSON.stringify({ SA_JSON: sa, DB_URL: Deno.env.get("DB_URL") ? "ok" : "missing" }), {
        headers: { ...cors(), "content-type": "application/json" },
      });
    }
    return reply("ok");
  }
  try {
    const { uid, nid } = await req.json();
    if (!uid || !nid || /[.#$\[\]\/]/.test(String(uid) + String(nid))) return reply("bad", 400);

    let sa: any = {};
    try { sa = JSON.parse(Deno.env.get("SA_JSON") || "{}"); } catch (_e) { sa = {}; }
    const DB = Deno.env.get("DB_URL") || "";
    const miss = [!sa.private_key && "SA_JSON", !DB && "DB_URL"].filter(Boolean);
    if (miss.length) return reply("not-configured:" + miss.join("+"), 500);

    const NN = Deno.env.get("NOTIF_NODE") || "user_notifications";
    const UN = Deno.env.get("USERS_NODE") || "users";
    const TF = Deno.env.get("TOKEN_FIELD") || "fcmToken";

    const tk = await accessToken(sa);
    const q = ".json?access_token=" + tk;

    const n = await (await fetch(`${DB}/${NN}/${uid}/${nid}${q}`)).json();
    if (!n || n.pushed) return reply("skip");

    const token = await (await fetch(`${DB}/${UN}/${uid}/${TF}${q}`)).json();
    if (!token) return reply("no-token");

    const r = await fetch(`https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`, {
      method: "POST",
      headers: { Authorization: "Bearer " + tk, "content-type": "application/json" },
      body: JSON.stringify({
        message: {
          token,
          notification: { title: n.title || "নোটিফিকেশন", body: n.body || "" },
          // CLICK_URL দিলে (পুরো https লিংক) ক্লিকে সেই লিংক খোলে। না দিলে অ্যাপের service worker নিজেই অ্যাপ খোলে।
          ...(Deno.env.get("CLICK_URL") ? { webpush: { fcm_options: { link: Deno.env.get("CLICK_URL") } } } : {}),
        },
      }),
    });

    if (r.ok) {
      await fetch(`${DB}/${NN}/${uid}/${nid}/pushed${q}`, { method: "PUT", body: "true" });
      return reply("sent");
    }
    if (r.status === 404) await fetch(`${DB}/${UN}/${uid}/${TF}${q}`, { method: "DELETE" }); // মেয়াদ শেষ টোকেন মুছে ফেলা
    return reply("fail", 502);
  } catch (_e) {
    return reply("error", 500);
  }
});
