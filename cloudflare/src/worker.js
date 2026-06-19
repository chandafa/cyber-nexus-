// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com
//
// Cloudflare Worker — server aktivasi lisensi Nexus (GRATIS, tanpa kartu).
//   POST /admin/generate  {count,tier,days}  (header x-admin-token)  -> buat kode di D1
//   POST /admin/revoke    {code}             (header x-admin-token)  -> cabut kode
//   POST /redeem_license  {code,deviceId}                            -> sekali pakai, kunci device, token Ed25519
//   POST /validate_license{code,deviceId}                            -> status terkini
//
// Penyimpanan: Cloudflare D1 (SQLite). Tanda tangan: WebCrypto Ed25519 dengan
// secret VENDOR_SEED (hex) — kompatibel byte-for-byte dengan verifier Python.

const TIER_FEATURES = {
  free: [],
  pro: ["sigma", "active_response", "advanced_rules", "webaudit", "report"],
  enterprise: ["unlimited_agents", "sigma", "active_response", "advanced_rules", "webaudit", "report"],
};
const DEFAULT_MAX_AGENTS = { free: 2, pro: 50, enterprise: 0 };
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // crockford base32 tanpa I,L,O,U
const PKCS8_PREFIX = Uint8Array.from(
  [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]
);

// --------------------------------------------------------------------- util
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

function hexToBytes(hex) {
  hex = hex.trim();
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
function genCode() {
  const grp = () => Array.from(randBytes(5)).map((x) => ALPHABET[x % 32]).join("");
  return `NEXUS-${grp()}-${grp()}-${grp()}-${grp()}`;
}
// JSON kanonik: kunci terurut + escape non-ASCII (samakan dengan Python ensure_ascii).
function canonical(obj) {
  const ordered = {};
  for (const k of Object.keys(obj).sort()) ordered[k] = obj[k];
  const s = JSON.stringify(ordered);
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += c > 0x7f ? "\\u" + c.toString(16).padStart(4, "0") : s[i];
  }
  return out;
}
async function signToken(seedHex, payload) {
  const seed = hexToBytes(seedHex);
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(seed, PKCS8_PREFIX.length);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  const raw = new TextEncoder().encode(canonical(payload));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, raw));
  return b64url(raw) + "." + b64url(sig);
}
async function issueToken(env, { tier, device, code, expires, licensee }) {
  return signToken(env.VENDOR_SEED, {
    id: b64url(randBytes(8)),
    tier,
    device,
    code,
    licensee: licensee || "",
    features: TIER_FEATURES[tier] || [],
    max_agents: DEFAULT_MAX_AGENTS[tier] ?? 2,
    issued: Math.floor(Date.now() / 1000),
    expires,
  });
}

async function readBody(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

// --------------------------------------------------------------------- handlers
async function adminGenerate(req, env) {
  if (req.headers.get("x-admin-token") !== env.ADMIN_TOKEN)
    return json({ ok: false, error: "unauthorized" }, 401);
  const b = await readBody(req);
  const count = Math.min(Math.max(parseInt(b.count || 1, 10), 1), 500);
  const tier = ["pro", "enterprise"].includes(b.tier) ? b.tier : "pro";
  const days = Math.min(Math.max(parseInt(b.days || 30, 10), 1), 3650);
  const now = Math.floor(Date.now() / 1000);
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = genCode();
    await env.DB.prepare(
      "INSERT INTO licenses (code,tier,status,duration_days,licensee,created_at) VALUES (?,?,'unused',?,?,?)"
    ).bind(code, tier, days, b.licensee || "", now).run();
    codes.push(code);
  }
  return json({ ok: true, count: codes.length, tier, days, codes });
}

async function adminRevoke(req, env) {
  if (req.headers.get("x-admin-token") !== env.ADMIN_TOKEN)
    return json({ ok: false, error: "unauthorized" }, 401);
  const { code } = await readBody(req);
  if (!code) return json({ ok: false, error: "missing_code" }, 400);
  const r = await env.DB.prepare("UPDATE licenses SET status='revoked' WHERE code=?")
    .bind(String(code).toUpperCase()).run();
  return json({ ok: true, revoked: r.meta.changes > 0 });
}

async function redeem(req, env) {
  const b = await readBody(req);
  const code = String(b.code || "").trim().toUpperCase();
  const device = String(b.deviceId || "").trim();
  if (!code || !device) return json({ ok: false, reason: "missing", error: "missing_code_or_device" }, 400);

  const row = await env.DB.prepare("SELECT * FROM licenses WHERE code=?").bind(code).first();
  if (!row) return json({ ok: false, reason: "invalid_code", error: "Kode tidak ditemukan." }, 409);
  if (row.status === "revoked") return json({ ok: false, reason: "revoked", error: "Kode dicabut." }, 409);

  const now = Math.floor(Date.now() / 1000);
  let expires;
  if (row.status === "redeemed") {
    if (row.device_id !== device)
      return json({ ok: false, reason: "used_other_device", error: "Kode sudah dipakai di perangkat lain." }, 409);
    expires = row.expires_at;
    if (expires && now > expires)
      return json({ ok: false, reason: "expired", error: "Kode kedaluwarsa." }, 409);
  } else {
    expires = now + row.duration_days * 86400;
    // Klaim ATOMIK: hanya berhasil bila masih 'unused' (anti dipakai 2x / 2 device).
    const upd = await env.DB.prepare(
      "UPDATE licenses SET status='redeemed', device_id=?, redeemed_at=?, expires_at=? WHERE code=? AND status='unused'"
    ).bind(device, now, expires, code).run();
    if (upd.meta.changes !== 1) {
      const cur = await env.DB.prepare("SELECT device_id, expires_at FROM licenses WHERE code=?").bind(code).first();
      if (cur && cur.device_id === device) {
        expires = cur.expires_at;
      } else {
        return json({ ok: false, reason: "used_other_device", error: "Kode sudah dipakai di perangkat lain." }, 409);
      }
    }
  }
  const token = await issueToken(env, { tier: row.tier, device, code, expires, licensee: row.licensee });
  return json({ ok: true, token, tier: row.tier, expiresAt: expires });
}

async function validate(req, env) {
  const b = await readBody(req);
  const code = String(b.code || "").trim().toUpperCase();
  const device = String(b.deviceId || "").trim();
  if (!code || !device) return json({ ok: false, error: "missing" }, 400);
  const row = await env.DB.prepare("SELECT * FROM licenses WHERE code=?").bind(code).first();
  if (!row) return json({ ok: true, status: "invalid" });
  if (row.status === "revoked") return json({ ok: true, status: "revoked" });
  if (row.status !== "redeemed") return json({ ok: true, status: "unused" });
  if (row.device_id !== device) return json({ ok: true, status: "used_other_device" });
  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at && now > row.expires_at)
    return json({ ok: true, status: "expired", expiresAt: row.expires_at });
  return json({ ok: true, status: "active", tier: row.tier, expiresAt: row.expires_at });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { status: 204 });
    if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    try {
      switch (url.pathname) {
        case "/admin/generate": return await adminGenerate(req, env);
        case "/admin/revoke": return await adminRevoke(req, env);
        case "/redeem_license": return await redeem(req, env);
        case "/validate_license": return await validate(req, env);
        default: return json({ ok: false, error: "not_found" }, 404);
      }
    } catch (e) {
      return json({ ok: false, error: "server_error", detail: String(e) }, 500);
    }
  },
};
