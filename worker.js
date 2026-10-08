const CORS = {
  "Access-Control-Allow-Origin": "https://ldlj.fun",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Content-Type": "application/json"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS
  });
}

function randomHex(bytes = 16) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return [...new Uint8Array(bits)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function tokenHash(token) {
  const data = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  return [...new Uint8Array(data)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function generateLDLJID() {
  return "LDLJ-" + new Date().getFullYear() + "-" +
    randomHex(4).toUpperCase();
}

async function body(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

export default {
  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return json({
        service: "LDLJ API",
        status: "online",
        database: "D1",
        version: "1.0"
      });
    }

    if (request.method !== "POST") {
      return json({ error: "Méthode non autorisée" }, 405);
    }

    if (url.pathname === "/api/register") {

      const data = await body(request);

      const first_name = String(data.first_name || "").trim();
      const last_name = String(data.last_name || "").trim();
      const phone = String(data.phone || "").trim();
      const password = String(data.password || "");

      if (!first_name || !last_name || !phone || password.length < 6) {
        return json({
          error: "Prénom, nom, téléphone et mot de passe de 6 caractères minimum requis."
        }, 400);
      }

      const existing = await env.DB
        .prepare("SELECT id FROM members WHERE phone = ?")
        .bind(phone)
        .first();

      if (existing) {
        return json({
          error: "Ce numéro de téléphone possède déjà un compte."
        }, 409);
      }

      const ldlj_id = generateLDLJID();
      const salt = randomHex(16);
      const password_hash = await hashPassword(password, salt);

      const result = await env.DB.prepare(`
        INSERT INTO members
        (ldlj_id, first_name, last_name, phone, password_hash, password_salt, status)
        VALUES (?, ?, ?, ?, ?, ?, 'PENDING')
      `).bind(
        ldlj_id,
        first_name,
        last_name,
        phone,
        password_hash,
        salt
      ).run();

      const memberId = result.meta.last_row_id;

      await env.DB.prepare(`
        INSERT INTO member_status_history
        (member_id, old_status, new_status, reason)
        VALUES (?, NULL, 'PENDING', 'Création du compte')
      `).bind(memberId).run();

      return json({
        success: true,
        message: "Compte créé. Validation LDLJ en attente.",
        ldlj_id,
        status: "PENDING"
      }, 201);
    }

    if (url.pathname === "/api/status") {

      const data = await body(request);
      const phone = String(data.phone || "").trim();
      const first_name = String(data.first_name || "").trim();
      const last_name = String(data.last_name || "").trim();

      let member;

      if (phone) {
        member = await env.DB.prepare(`
          SELECT ldlj_id, first_name, last_name, phone, status, created_at
          FROM members
          WHERE phone = ?
        `).bind(phone).first();
      } else if (first_name && last_name) {
        member = await env.DB.prepare(`
          SELECT ldlj_id, first_name, last_name, phone, status, created_at
          FROM members
          WHERE LOWER(first_name)=LOWER(?) AND LOWER(last_name)=LOWER(?)
          LIMIT 1
        `).bind(first_name, last_name).first();
      }

      if (!member) {
        return json({
          found: false,
          message: "Aucun membre correspondant."
        }, 404);
      }

      return json({
        found: true,
        member
      });
    }

    if (url.pathname === "/api/login") {

      const data = await body(request);

      const identifier = String(data.identifier || "").trim();
      const password = String(data.password || "");

      if (!identifier || !password) {
        return json({
          error: "Identifiant et mot de passe requis."
        }, 400);
      }

      const member = await env.DB.prepare(`
        SELECT *
        FROM members
        WHERE phone = ? OR ldlj_id = ?
        LIMIT 1
      `).bind(identifier, identifier).first();

      if (!member) {
        return json({
          error: "Identifiant ou mot de passe incorrect."
        }, 401);
      }

      const calculated = await hashPassword(
        password,
        member.password_salt
      );

      if (calculated !== member.password_hash) {
        return json({
          error: "Identifiant ou mot de passe incorrect."
        }, 401);
      }

      const token = randomHex(32);
      const token_hash = await tokenHash(token);

      await env.DB.prepare(`
        INSERT INTO sessions
        (member_id, token_hash, expires_at)
        VALUES (?, ?, datetime('now', '+30 days'))
      `).bind(
        member.id,
        token_hash
      ).run();

      return json({
        success: true,
        message: "Connexion réussie.",
        token,
        member: {
          ldlj_id: member.ldlj_id,
          first_name: member.first_name,
          last_name: member.last_name,
          phone: member.phone,
          status: member.status
        }
      });
    }

    if (url.pathname === "/api/me") {

      const auth = request.headers.get("Authorization") || "";

      if (!auth.startsWith("Bearer ")) {
        return json({
          error: "Authentification requise."
        }, 401);
      }

      const token = auth.substring(7);
      const hash = await tokenHash(token);

      const member = await env.DB.prepare(`
        SELECT m.ldlj_id, m.first_name, m.last_name,
               m.phone, m.status, m.created_at
        FROM sessions s
        JOIN members m ON m.id = s.member_id
        WHERE s.token_hash = ?
        AND datetime(s.expires_at) > datetime('now')
        LIMIT 1
      `).bind(hash).first();

      if (!member) {
        return json({
          error: "Session invalide ou expirée."
        }, 401);
      }

      return json({
        success: true,
        member
      });
    }

    return json({
      error: "Route inconnue"
    }, 404);
  }
};
