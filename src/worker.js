// --- CONFIG: allowed frontends that can call this API ---
const ALLOWED_ORIGINS = [
  "https://riskxlabs-box-cloudflare-v2.agedotcom.workers.dev",
  // TODO: replace this with your real GitHub Pages origin:
  // e.g. "https://yourusername.github.io"
  "https://agethejedi.github.io"
];

const SESSION_COOKIE = "box_session";
const SESSION_TTL_HOURS = 24;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env, ctx);
    }

    // static assets (served by Cloudflare)
    return env.ASSETS.fetch(request);
  }
};

// ---------- helpers ----------

function getAllowedOrigin(request) {
  const origin = request.headers.get("Origin") || "";
  if (ALLOWED_ORIGINS.includes(origin)) return origin;
  return "";
}

function jsonResponse(request, status, body, extraHeaders = {}) {
  const allowedOrigin = getAllowedOrigin(request);
  const base = {
    "Content-Type": "application/json"
  };
  if (allowedOrigin) {
    base["Access-Control-Allow-Origin"] = allowedOrigin;
    base["Access-Control-Allow-Credentials"] = "true";
  }
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...base,
      ...extraHeaders
    }
  });
}

async function parseJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;
  const parts = cookie.split(";").map((c) => c.trim());
  for (const part of parts) {
    if (part.startsWith(name + "=")) {
      return decodeURIComponent(part.substring(name.length + 1));
    }
  }
  return null;
}

// NOTE: cross-site admin from GitHub Pages needs SameSite=None + Secure
function setSessionCookie(sessionId) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(sessionId)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=None",
    "Secure"
  ].join("; ");
}

async function requireAdmin(request, env) {
  const sid = getCookie(request, SESSION_COOKIE);
  if (!sid) {
    throw { status: 401, body: { ok: false, message: "Not authenticated" } };
  }
  const nowIso = new Date().toISOString();
  const sessionRow = await env.BOX_DB.prepare(
    "SELECT admin_email, expires_at FROM sessions WHERE id = ?"
  )
    .bind(sid)
    .first();
  if (!sessionRow) {
    throw { status: 401, body: { ok: false, message: "Invalid session" } };
  }
  if (sessionRow.expires_at <= nowIso) {
    await env.BOX_DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sid).run();
    throw { status: 401, body: { ok: false, message: "Session expired" } };
  }
  return sessionRow.admin_email;
}

function generateBoxCode() {
  const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const letter = letters[Math.floor(Math.random() * letters.length)];
  let digits = "";
  for (let i = 0; i < 6; i++) {
    digits += Math.floor(Math.random() * 10).toString();
  }
  return letter + digits;
}

async function refreshExpirations(env) {
  const nowIso = new Date().toISOString();
  await env.BOX_DB.prepare(
    "UPDATE boxes SET status = 'expired_unused' WHERE status = 'waiting_for_address' AND expires_at < ?"
  )
    .bind(nowIso)
    .run();
}

// ---------- main API handler ----------

async function handleApi(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS preflight for GitHub Pages → Worker
  if (request.method === "OPTIONS") {
    const allowedOrigin = getAllowedOrigin(request);
    return new Response(null, {
      status: 204,
      headers: {
        ...(allowedOrigin
          ? {
              "Access-Control-Allow-Origin": allowedOrigin,
              "Access-Control-Allow-Credentials": "true"
            }
          : {}),
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      }
    });
  }

  try {
    // ----- ADMIN LOGIN -----
    if (path === "/api/admin/login" && request.method === "POST") {
      const body = await parseJson(request);
      const email = (body.email || "").trim();
      const password = body.password || "";
      if (!email || !password) {
        return jsonResponse(request, 400, {
          ok: false,
          message: "Email and password required."
        });
      }
      const expected = env.ADMIN_PASSWORD;
      if (!expected) {
        return jsonResponse(request, 500, {
          ok: false,
          message: "ADMIN_PASSWORD not configured."
        });
      }
      if (password !== expected) {
        return jsonResponse(request, 401, {
          ok: false,
          message: "Invalid credentials."
        });
      }

      // Ensure admin exists (SQLite / D1 friendly)
      try {
        await env.BOX_DB.prepare(
          "INSERT OR IGNORE INTO admins (email) VALUES (?)"
        )
          .bind(email)
          .run();
      } catch (e) {
        console.error("Failed to insert admin:", e);
      }

      const sessionId = crypto.randomUUID();
      const now = new Date();
      const expires = new Date(now.getTime() + SESSION_TTL_HOURS * 60 * 60 * 1000);
      await env.BOX_DB.prepare(
        "INSERT INTO sessions (id, admin_email, created_at, expires_at) VALUES (?, ?, ?, ?)"
      )
        .bind(sessionId, email, now.toISOString(), expires.toISOString())
        .run();

      const cookie = setSessionCookie(sessionId);
      return jsonResponse(request, 200, { ok: true }, {
        "Set-Cookie": cookie
      });
    }

    // ----- ADMIN LOGOUT -----
    if (path === "/api/admin/logout" && request.method === "POST") {
      const sid = getCookie(request, SESSION_COOKIE);
      if (sid) {
        await env.BOX_DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sid).run();
      }
      const expiredCookie = `${SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0; SameSite=None; Secure`;
      return jsonResponse(request, 200, { ok: true }, {
        "Set-Cookie": expiredCookie
      });
    }

    // ----- ADMIN: who am I -----
    if (path === "/api/admin/me" && request.method === "GET") {
      const email = await requireAdmin(request, env);
      return jsonResponse(request, 200, { ok: true, admin: { email } });
    }

    // ----- CUSTOMER: submit address -----
    if (path === "/api/box/submit" && request.method === "POST") {
      await refreshExpirations(env);
      const body = await parseJson(request);
      const code = String(body.code || "").trim().toUpperCase();
      const cryptoAddress = (body.crypto_address || "").trim();
      if (!code || !cryptoAddress) {
        return jsonResponse(request, 400, {
          ok: false,
          message: "Code and crypto_address required."
        });
      }
      if (!/^[A-Z][0-9]{6}$/.test(code)) {
        return jsonResponse(request, 400, {
          ok: false,
          message: "Invalid code format."
        });
      }

      const box = await env.BOX_DB.prepare("SELECT * FROM boxes WHERE code = ?")
        .bind(code)
        .first();
      if (!box) {
        return jsonResponse(request, 404, {
          ok: false,
          message: "Invalid or unknown Box Code."
        });
      }
      if (box.status !== "waiting_for_address") {
        return jsonResponse(request, 400, {
          ok: false,
          message: "This Box is no longer accepting addresses."
        });
      }
      const now = new Date();
      const exp = new Date(box.expires_at);
      if (exp < now) {
        await env.BOX_DB.prepare(
          "UPDATE boxes SET status = 'expired_unused' WHERE id = ?"
        )
          .bind(box.id)
          .run();
        return jsonResponse(request, 400, {
          ok: false,
          message: "This Box Code has expired. Ask your admin for a new one."
        });
      }

      await env.BOX_DB.prepare(
        "UPDATE boxes SET crypto_address = ?, status = 'address_submitted', submitted_at = ? WHERE id = ?"
      )
        .bind(cryptoAddress, now.toISOString(), box.id)
        .run();

      return jsonResponse(request, 200, {
        ok: true,
        message: "Address submitted."
      });
    }

    // ----- ADMIN: create new code -----
    if (path === "/api/admin/create-code" && request.method === "POST") {
      const adminEmail = await requireAdmin(request, env);
      await refreshExpirations(env);

      let code;
      let attempts = 0;
      while (attempts < 20) {
        attempts++;
        code = generateBoxCode();
        const existing = await env.BOX_DB.prepare("SELECT id FROM boxes WHERE code = ?")
          .bind(code)
          .first();
        if (!existing) break;
        code = null;
      }
      if (!code) {
        return jsonResponse(request, 500, {
          ok: false,
          message: "Unable to generate unique code."
        });
      }

      const now = new Date();
      const exp = new Date(now.getTime() + 15 * 60 * 1000);
      const id = crypto.randomUUID();
      await env.BOX_DB.prepare(
        "INSERT INTO boxes (id, code, status, crypto_address, created_at, expires_at, submitted_at, retrieved_at, created_by_admin_email, last_retrieved_by_admin_email) VALUES (?, ?, 'waiting_for_address', NULL, ?, ?, NULL, NULL, ?, NULL)"
      )
        .bind(id, code, now.toISOString(), exp.toISOString(), adminEmail)
        .run();

      return jsonResponse(request, 200, {
        ok: true,
        code,
        box: {
          id,
          code,
          status: "waiting_for_address",
          crypto_address: null,
          created_at: now.toISOString(),
          expires_at: exp.toISOString(),
          submitted_at: null,
          retrieved_at: null,
          created_by_admin_email: adminEmail,
          last_retrieved_by_admin_email: null
        }
      });
    }

    // ----- ADMIN: my codes (active / recent) -----
    if (path === "/api/admin/my-codes" && request.method === "GET") {
      const adminEmail = await requireAdmin(request, env);
      await refreshExpirations(env);
      const scope = url.searchParams.get("scope") || "active";
      const now = new Date();
      const nowIso = now.toISOString();
      const twelveHoursAgo = new Date(now.getTime() - 12 * 60 * 60 * 1000).toISOString();

      let query;
      let args;
      if (scope === "recent" || scope === "expired") {
        query = `
          SELECT * FROM boxes
          WHERE created_by_admin_email = ?
            AND expires_at <= ?
            AND expires_at >= ?
          ORDER BY expires_at DESC
        `;
        args = [adminEmail, nowIso, twelveHoursAgo];
      } else {
        query = `
          SELECT * FROM boxes
          WHERE created_by_admin_email = ?
            AND expires_at > ?
            AND status IN ('waiting_for_address', 'address_submitted')
          ORDER BY created_at DESC
        `;
        args = [adminEmail, nowIso];
      }

      const res = await env.BOX_DB.prepare(query).bind(...args).all();
      return jsonResponse(request, 200, {
        ok: true,
        boxes: res.results || []
      });
    }

    // ----- ADMIN: lookup any code -----
    if (path === "/api/admin/lookup" && request.method === "POST") {
      await requireAdmin(request, env);
      await refreshExpirations(env);
      const body = await parseJson(request);
      const code = String(body.code || "").trim().toUpperCase();
      if (!code) {
        return jsonResponse(request, 400, {
          ok: false,
          message: "Code required."
        });
      }
      if (!/^[A-Z][0-9]{6}$/.test(code)) {
        return jsonResponse(request, 400, {
          ok: false,
          message: "Invalid code format."
        });
      }
      const box = await env.BOX_DB.prepare("SELECT * FROM boxes WHERE code = ?")
        .bind(code)
        .first();
      if (!box) {
        return jsonResponse(request, 404, {
          ok: false,
          message: "Box not found."
        });
      }
      return jsonResponse(request, 200, { ok: true, box });
    }

    // ----- ADMIN: retrieve full address -----
    if (path === "/api/admin/retrieve" && request.method === "POST") {
      const adminEmail = await requireAdmin(request, env);
      await refreshExpirations(env);
      const body = await parseJson(request);
      const code = String(body.code || "").trim().toUpperCase();
      if (!code) {
        return jsonResponse(request, 400, {
          ok: false,
          message: "Code required."
        });
      }
      if (!/^[A-Z][0-9]{6}$/.test(code)) {
        return jsonResponse(request, 400, {
          ok: false,
          message: "Invalid code format."
        });
      }

      const box = await env.BOX_DB.prepare("SELECT * FROM boxes WHERE code = ?")
        .bind(code)
        .first();
      if (!box) {
        return jsonResponse(request, 404, {
          ok: false,
          message: "Box not found."
        });
      }

      const now = new Date();
      const exp = new Date(box.expires_at);
      if (exp < now) {
        await env.BOX_DB.prepare(
          "UPDATE boxes SET status = 'expired_unused' WHERE id = ?"
        )
          .bind(box.id)
          .run();
        return jsonResponse(request, 400, {
          ok: false,
          message: "Box has expired."
        });
      }
      if (box.status !== "address_submitted") {
        return jsonResponse(request, 400, {
          ok: false,
          message: "Box not in a retrievable state."
        });
      }

      await env.BOX_DB.prepare(
        "UPDATE boxes SET status = 'consumed', retrieved_at = ?, last_retrieved_by_admin_email = ? WHERE id = ?"
      )
        .bind(now.toISOString(), adminEmail, box.id)
        .run();
      const updated = await env.BOX_DB.prepare(
        "SELECT crypto_address FROM boxes WHERE id = ?"
      )
        .bind(box.id)
        .first();

      return jsonResponse(request, 200, {
        ok: true,
        crypto_address: updated.crypto_address
      });
    }

    // fallback
    return jsonResponse(request, 404, { ok: false, message: "Not found" });
  } catch (err) {
    if (err && typeof err.status === "number" && err.body) {
      return jsonResponse(request, err.status, err.body);
    }
    console.error("Worker error", err);
    return jsonResponse(request, 500, { ok: false, message: "Internal error" });
  }
}
