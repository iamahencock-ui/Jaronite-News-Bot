import { getAssetFromKV } from "@cloudflare/kv-asset-handler";
import manifestJSON from "__STATIC_CONTENT_MANIFEST";

const assetManifest = JSON.parse(manifestJSON);

// ---------- password hashing (Web Crypto PBKDF2, no extra deps) ----------

/**
 * Convert a binary buffer (ArrayBuffer or typed array) into a lowercase hex string.
 * Used to turn raw crypto output (hashes, salts, session tokens) into a
 * string that's safe to store in D1 and send over JSON.
 * @param {ArrayBuffer} buf - The raw bytes to encode.
 * @returns {string} Hex-encoded representation of the buffer.
 */
function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Convert a hex string back into a raw binary buffer. The inverse of bufToHex.
 * Used to recover a previously-stored salt (saved as hex in D1) into the
 * ArrayBuffer form the Web Crypto API expects.
 * @param {string} hex - Hex-encoded byte string.
 * @returns {ArrayBuffer} The decoded raw bytes.
 */
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes.buffer;
}

/**
 * Hash a plaintext password with PBKDF2 (100,000 iterations, SHA-256).
 * If saltHex is omitted, a fresh random 16-byte salt is generated — use this
 * path when creating a new password. Pass an existing saltHex (read from the
 * users table) when re-deriving a hash to verify a login attempt, so the
 * same salt produces a comparable hash.
 * @param {string} password - The plaintext password to hash.
 * @param {string} [saltHex] - An existing hex-encoded salt to reuse, or omit to generate a new one.
 * @returns {Promise<{hash: string, salt: string}>} The hex-encoded derived hash and the salt used.
 */
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { hash: bufToHex(bits), salt: bufToHex(salt) };
}

/**
 * Hash an article's title+content with SHA-256 for integrity polling.
 * Not a security/auth hash (no salt, no secret) — just a cheap fingerprint
 * so a reader's open tab can tell "did this article's published text
 * change" without re-downloading and diffing the full body every few
 * seconds. Title and content are joined with a separator unlikely to
 * appear naturally, so e.g. title:"AB" + content:"C" can't collide with
 * title:"A" + content:"BC".
 * @param {string} title
 * @param {string} content
 * @returns {Promise<string>} Hex-encoded SHA-256 hash.
 */
async function hashArticleText(title, content) {
  const enc = new TextEncoder();
  const bits = await crypto.subtle.digest("SHA-256", enc.encode(`${title}\u0000${content}`));
  return bufToHex(bits);
}

/**
 * Check a login attempt's plaintext password against a stored PBKDF2 hash.
 * Re-derives the hash using the stored salt, then compares byte-by-byte in
 * constant time (XOR-accumulate over the whole string) to avoid leaking
 * timing information that could help an attacker guess the password.
 * @param {string} password - The plaintext password supplied at login.
 * @param {string} storedHash - The hex-encoded hash stored in the users table.
 * @param {string} storedSaltHex - The hex-encoded salt stored alongside that hash.
 * @returns {Promise<boolean>} True if the password is correct.
 */

// ---------- security headers ----------

/**
/**
 * Constant-time string comparison. Avoids leaking how many leading
 * characters of a secret matched via response-timing differences.
 * Callers must check length equality first (this assumes equal length).
 */
function timingSafeEqualStr(a, b) {
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Standard security headers added to every HTML/API response.
 * CSP stops injected scripts; the rest are defence-in-depth headers that
 * cost nothing but significantly raise the bar for common attack classes.
 */
function securityHeaders(extraHeaders = {}) {
  return {
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https://cdn.discordapp.com data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none';",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    ...extraHeaders,
  };
}

/**
 * Wrap a JSON response with security headers.
 */
function secureJson(data, init = {}) {
  const res = Response.json(data, init);
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(securityHeaders())) headers.set(k, v);
  return new Response(res.body, { status: res.status, headers });
}


// ================================================================
// Resend email helper
// Uses the Resend API (https://resend.com) — free tier, no smtp config.
// Requires: RESEND_API_KEY secret  (npx wrangler secret put RESEND_API_KEY)
//           RESEND_FROM_EMAIL env var in wrangler.toml, e.g. "ads@jaronitenews.com"
// ================================================================
async function sendEmail(env, { to, subject, html }) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) { console.warn('RESEND_API_KEY not set — email skipped'); return; }
  const from = env.RESEND_FROM_EMAIL || 'Jaronite News <ads@jaronitenews.com>';
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from, to, subject, html }),
    });
    if (!res.ok) {
      const err = await res.text();
      console.error('Resend error:', res.status, err);
    }
  } catch (e) {
    console.error('Resend fetch failed:', e);
  }
}


// ================================================================
// Discord DM helper — sends a DM to a user by username via bot
// Requires: DISCORD_BOT_TOKEN secret  (npx wrangler secret put DISCORD_BOT_TOKEN)
// Flow: search for user by username → open DM channel → send message
// Note: the bot must share a server with the recipient, or have
//       the MESSAGE_CONTENT intent enabled in the Developer Portal.
// ================================================================
async function sendDiscordDm(env, discordUsername, message) {
  const token = env.DISCORD_BOT_TOKEN;
  if (!token) { console.warn('DISCORD_BOT_TOKEN not set — Discord DM skipped'); return; }
  if (!discordUsername) return;

  try {
    // Strip any #discriminator suffix (legacy tags like user#1234)
    const username = discordUsername.replace(/#\d{4}$/, '').trim();

    // Search for the user via the bot's guild member search.
    // We search the configured guild (server) for the username.
    const guildId = env.DISCORD_GUILD_ID;
    if (!guildId) { console.warn('DISCORD_GUILD_ID not set — Discord DM skipped'); return; }

    const searchRes = await fetch(
      `https://discord.com/api/v10/guilds/${guildId}/members/search?query=${encodeURIComponent(username)}&limit=5`,
      { headers: { Authorization: `Bot ${token}` } }
    );
    if (!searchRes.ok) {
      console.error('Discord member search failed:', searchRes.status, await searchRes.text());
      return;
    }
    const members = await searchRes.json();
    // Find the closest match — prefer exact username match
    const member = members.find(m =>
      m.user.username.toLowerCase() === username.toLowerCase() ||
      (m.nick && m.nick.toLowerCase() === username.toLowerCase())
    ) || members[0];

    if (!member) {
      console.warn(`Discord: could not find user "${username}" in guild`);
      return;
    }
    const userId = member.user.id;

    // Open a DM channel
    const dmRes = await fetch('https://discord.com/api/v10/users/@me/channels', {
      method: 'POST',
      headers: { Authorization: `Bot ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipient_id: userId }),
    });
    if (!dmRes.ok) {
      console.error('Discord DM channel open failed:', dmRes.status, await dmRes.text());
      return;
    }
    const dmChannel = await dmRes.json();

    // Send the message
    const msgRes = await fetch(`https://discord.com/api/v10/channels/${dmChannel.id}/messages`, {
      method: 'POST',
      headers: { Authorization: `Bot ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: message }),
    });
    if (!msgRes.ok) {
      console.error('Discord message send failed:', msgRes.status, await msgRes.text());
    }
  } catch (e) {
    console.error('Discord DM failed:', e);
  }
}

function winDiscordMsg(bid, slotLabel) {
  return `🎉 **You won a Jaronite News ad slot!**

Hi **${bid.advertiser_name}** — your bid of **${Number(bid.bid_amount).toFixed(2)} ℐ/view** won the **${slotLabel}** slot for **${bid.target_date}**.

**How to pay:**
Send payment in-game to the Jaronite News firm account with this exact memo:
\`\`\`
bid:${bid.id}
\`\`\`
Include \`bid:${bid.id}\` in the memo/message so we match your payment automatically.

Questions? Reply here or contact us on the DemocracyCraft Discord.
— Jaronite News Inc.`;
}

function confirmedDiscordMsg(bid, slotLabel, amount) {
  return `✅ **Payment received — your ad is confirmed!**

Hi **${bid.advertiser_name}** — we received your payment of **${Number(amount).toFixed(2)} ℐ** for bid **#${bid.id}** (${slotLabel}, ${bid.target_date}).

Your ad is confirmed and will run as scheduled. You'll receive a performance report after it runs.
— Jaronite News Inc.`;
}

function reminderDiscordMsg(bid, slotLabel) {
  return `⏰ **Reminder: payment pending for your Jaronite News ad**

Hi **${bid.advertiser_name}** — your winning ad bid is still awaiting payment.

**Slot:** ${slotLabel}  
**Date:** ${bid.target_date}  
**Rate:** ${Number(bid.bid_amount).toFixed(2)} ℐ/view  
**Bid ID:** #${bid.id}

Pay in-game with memo \`bid:${bid.id}\` to the Jaronite News firm account. If payment isn't received before ${bid.target_date}, your slot may be forfeited.
— Jaronite News Inc.`;
}

function winEmailHtml(bid, slotLabel) {
  const totalEstimate = (bid.bid_amount * 100).toFixed(2); // rough estimate: 100 views/day
  return `
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#222;">
  <h2 style="color:#5b3fa0;">🎉 You won an ad slot on Jaronite News!</h2>
  <p>Hi <strong>${bid.advertiser_name}</strong>,</p>
  <p>Your bid of <strong>${Number(bid.bid_amount).toFixed(2)} ℐ/view</strong> won the
     <strong>${slotLabel}</strong> slot for <strong>${bid.target_date}</strong>.</p>
  <h3 style="color:#5b3fa0;">How to pay</h3>
  <p>Transfer payment to the <strong>Jaronite News Inc.</strong> firm account in-game using:</p>
  <div style="background:#f3f0ff;border-left:4px solid #5b3fa0;padding:12px 16px;border-radius:4px;font-family:monospace;font-size:1.05em;">
    /pay JaroniteNews &lt;amount&gt; bid:${bid.id}
  </div>
  <p style="color:#666;font-size:0.9em;">
    Include <strong>bid:${bid.id}</strong> exactly as shown in the memo/message field so we can match your payment automatically.<br>
    You pay based on actual views — we'll send a final invoice after your ad runs.
  </p>
  <h3 style="color:#5b3fa0;">Your bid details</h3>
  <table style="width:100%;border-collapse:collapse;font-size:0.95em;">
    <tr><td style="padding:6px 0;color:#666;">Bid ID</td><td><strong>#${bid.id}</strong></td></tr>
    <tr><td style="padding:6px 0;color:#666;">Slot</td><td><strong>${slotLabel}</strong></td></tr>
    <tr><td style="padding:6px 0;color:#666;">Date</td><td><strong>${bid.target_date}</strong></td></tr>
    <tr><td style="padding:6px 0;color:#666;">Rate</td><td><strong>${Number(bid.bid_amount).toFixed(2)} ℐ/view</strong></td></tr>
  </table>
  <p style="margin-top:24px;color:#888;font-size:0.85em;">
    Questions? Reply to this email or contact us on Discord.<br>
    — Jaronite News Inc.
  </p>
</div>`;
}

function paymentConfirmedEmailHtml(bid, slotLabel, amount) {
  return `
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#222;">
  <h2 style="color:#27ae60;">✅ Payment received — your ad is confirmed!</h2>
  <p>Hi <strong>${bid.advertiser_name}</strong>,</p>
  <p>We received your payment of <strong>${Number(amount).toFixed(2)} ℐ</strong> for bid <strong>#${bid.id}</strong>
     (${slotLabel}, ${bid.target_date}). Your ad is confirmed and will run as scheduled.</p>
  <p>After your ad runs you'll receive a performance report with impressions, clicks, and your final cost.</p>
  <p style="margin-top:24px;color:#888;font-size:0.85em;">— Jaronite News Inc.</p>
</div>`;
}

function reminderEmailHtml(bid, slotLabel, daysOverdue) {
  return `
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#222;">
  <h2 style="color:#e67e22;">⏰ Reminder: payment pending for your ad slot</h2>
  <p>Hi <strong>${bid.advertiser_name}</strong>,</p>
  <p>This is a friendly reminder that payment for your winning ad bid is still outstanding.</p>
  <div style="background:#fff8f0;border-left:4px solid #e67e22;padding:12px 16px;border-radius:4px;font-family:monospace;font-size:1.05em;">
    /pay JaroniteNews &lt;amount&gt; bid:${bid.id}
  </div>
  <p style="color:#666;font-size:0.9em;">
    Include <strong>bid:${bid.id}</strong> in the memo. If payment isn't received before your ad date (${bid.target_date}),
    your slot may be forfeited.
  </p>
  <table style="width:100%;border-collapse:collapse;font-size:0.95em;margin-top:12px;">
    <tr><td style="padding:6px 0;color:#666;">Bid ID</td><td><strong>#${bid.id}</strong></td></tr>
    <tr><td style="padding:6px 0;color:#666;">Slot</td><td><strong>${slotLabel}</strong></td></tr>
    <tr><td style="padding:6px 0;color:#666;">Date</td><td><strong>${bid.target_date}</strong></td></tr>
    <tr><td style="padding:6px 0;color:#666;">Rate</td><td><strong>${Number(bid.bid_amount).toFixed(2)} ℐ/view</strong></td></tr>
  </table>
  <p style="margin-top:24px;color:#888;font-size:0.85em;">— Jaronite News Inc.</p>
</div>`;
}

const SLOT_LABELS = { 1: 'Bottom Leaderboard (728×90)', 2: 'Left Skyscraper (160×600)', 3: 'Right Skyscraper (160×600)' };

// ---------- in-memory rate limiting ----------
//
// Simple token-bucket per key (IP-based for login; user-id-based for comments).
// Workers are single-threaded, so no locking needed. The map is bounded by
// keeping only the last-seen timestamp per key — entries expire naturally as
// the map is pruned on each check. This is best-effort (resets on Worker
// restart / new isolate), not a hard guarantee, but it's sufficient to slow
// down brute-force and comment-spam attacks significantly.

const rateLimitStore = new Map(); // key -> { count, windowStart }

/**
 * Check whether a key has exceeded its rate limit.
 * @param {string} key        - Unique identifier (e.g. IP, user id).
 * @param {number} maxCalls   - Maximum calls allowed in the window.
 * @param {number} windowMs   - Window length in milliseconds.
 * @returns {boolean} true if the request should be blocked.
 */
function isRateLimited(key, maxCalls, windowMs) {
  const now = Date.now();
  let entry = rateLimitStore.get(key);
  if (!entry || now - entry.windowStart > windowMs) {
    entry = { count: 1, windowStart: now };
    rateLimitStore.set(key, entry);
    return false;
  }
  entry.count++;
  if (entry.count > maxCalls) return true;
  return false;
}

// Prune stale entries periodically so the map doesn't grow unboundedly.
// Called on each rate-limit check — O(n) but the map stays small in practice.
function pruneRateLimitStore(maxAgeMs = 60_000) {
  const cutoff = Date.now() - maxAgeMs;
  for (const [key, entry] of rateLimitStore) {
    if (entry.windowStart < cutoff) rateLimitStore.delete(key);
  }
}

const VALID_CATEGORIES = new Set(["politics", "economy", "guides", "miscellaneous"]);
const MAX_TITLE_LEN   = 300;
const MAX_CONTENT_LEN = 100_000;
const MAX_COMMENT_LEN = 2000;
const MAX_IMAGE_BYTES = 800_000; // ~800 KB base64 data URL

/**
 * Validate an image_url field: must be null/undefined, or a data URL
 * with a safe image MIME type and within the size cap.
 * @param {any} val
 * @returns {string|null} cleaned value or null
 */
function validateImageUrl(val) {
  if (!val) return null;
  if (typeof val !== "string") return null;
  if (!val.startsWith("data:image/")) return null;
  const allowed = ["data:image/jpeg;base64,", "data:image/jpg;base64,", "data:image/png;base64,", "data:image/gif;base64,", "data:image/webp;base64,"];
  if (!allowed.some(prefix => val.startsWith(prefix))) return null;
  if (val.length > MAX_IMAGE_BYTES) return null;
  return val;
}

async function verifyPassword(password, storedHash, storedSaltHex) {
  const { hash } = await hashPassword(password, storedSaltHex);
  if (hash.length !== storedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  return diff === 0;
}

/**
 * Generate a fresh, cryptographically random session token (32 random bytes,
 * hex-encoded to 64 characters). Issued on every successful login and stored
 * in the sessions table; the client sends it back as a Bearer token on every
 * subsequent authenticated request.
 * @returns {string} A new random hex session token.
 */
function newSessionToken() {
  return bufToHex(crypto.getRandomValues(new Uint8Array(32)).buffer);
}

// ---------- session-based auth ----------

/**
 * Resolve the currently authenticated user from a request's Bearer token.
 * Looks up the session, rejects it if missing/expired, then loads the
 * matching user and rejects if they're suspended. On success, also extends
 * the session's expiry by 20 minutes (sliding expiry) so active users don't
 * get logged out mid-session.
 * @param {object} env - Worker environment bindings (used for env.DB).
 * @param {Request} request - The incoming request, read for its Authorization header.
 * @returns {Promise<{id: number, username: string, role: string, status: string}|null>}
 *   The authenticated user record, or null if there's no valid session.
 */
async function getSessionUser(env, request) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return null;

  const session = await env.DB.prepare(
    "SELECT username, expires_at FROM sessions WHERE token = ?"
  ).bind(token).first();
  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) return null;

  const user = await env.DB.prepare(
    "SELECT id, username, role, status FROM users WHERE username = ?"
  ).bind(session.username).first();
  if (!user || user.status !== "active") return null;

  // Sliding expiry: every valid authenticated request pushes the session's
  // expiry 20 minutes further out, so active users stay logged in and only
  // truly idle sessions (20 min with no requests) expire.
  const newExpiresAt = new Date(Date.now() + 1000 * 60 * 20).toISOString();
  await env.DB.prepare("UPDATE sessions SET expires_at = ? WHERE token = ?").bind(newExpiresAt, token).run();

  return user;
}

/**
 * Authenticate a request and require the user to hold the 'admin' role.
 * Thin wrapper around getSessionUser that adds a role check — use at the top
 * of any /api/admin/* route handler.
 * @param {object} env - Worker environment bindings.
 * @param {Request} request - The incoming request.
 * @returns {Promise<object|null>} The admin user record, or null if unauthenticated or not an admin.
 */
async function requireAdmin(env, request) {
  const user = await getSessionUser(env, request);
  if (!user || user.role !== "admin") return null;
  return user;
}

/**
 * Authenticate a request and require the user to hold the 'editor' or
 * 'admin' role. Anything an editor can do, an admin can also do — use at
 * the top of any /api/editor/* route handler (and any route shared between
 * editors and admins).
 * @param {object} env - Worker environment bindings.
 * @param {Request} request - The incoming request.
 * @returns {Promise<object|null>} The user record, or null if unauthenticated or neither editor nor admin.
 */
async function requireEditorOrAdmin(env, request) {
  const user = await getSessionUser(env, request);
  if (!user || (user.role !== "editor" && user.role !== "admin")) return null;
  return user;
}

// ---------- Discord OAuth2 (public reader accounts) ----------
//
// Entirely separate identity system from staff `users`/`sessions` above.
// Readers authenticate via Discord's OAuth2 authorization-code flow, never
// supply or store a local password, and the resulting session only ever
// grants access to reader-level actions (commenting, favoriting). It can
// never satisfy requireAdmin/requireEditorOrAdmin/getSessionUser, since
// those query the unrelated `sessions`/`users` tables.

/**
 * Resolve the currently authenticated Discord reader from a request's
 * Bearer token, against the discord_sessions/discord_users tables. Mirrors
 * getSessionUser's shape and sliding-expiry behavior so the two auth
 * systems are easy to reason about side-by-side, but never cross-reads
 * the staff tables.
 * @param {object} env - Worker environment bindings (env.DB).
 * @param {Request} request - The incoming request, read for its Authorization header.
 * @returns {Promise<{id: number, discord_id: string, username: string, avatar_hash: string|null}|null>}
 */
async function getDiscordSessionUser(env, request) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return null;

  const session = await env.DB.prepare(
    "SELECT discord_user_id, expires_at FROM discord_sessions WHERE token = ?"
  ).bind(token).first();
  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) return null;

  const user = await env.DB.prepare(
    "SELECT id, discord_id, username, avatar_hash, status FROM discord_users WHERE id = ?"
  ).bind(session.discord_user_id).first();
  if (!user || user.status !== "active") return null;

  // Reader sessions last longer than staff sessions (30 days vs 20 min) —
  // readers expect to stay logged in across visits like any normal site,
  // staff sessions are deliberately short for an internal admin tool.
  const newExpiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
  await env.DB.prepare("UPDATE discord_sessions SET expires_at = ? WHERE token = ?").bind(newExpiresAt, token).run();

  return user;
}

/**
 * Write one entry to the audit log (logs table). Called after nearly every
 * state-changing action across the app — logins, article lifecycle events,
 * and admin/user-management actions — so the Logs tab in the portal has a
 * complete trail of who did what and when.
 * @param {object} env - Worker environment bindings.
 * @param {string} username - The actor performing the action.
 * @param {string} action - A short machine-readable action code (e.g. "LOGIN", "APPROVE_ARTICLE").
 * @param {string} [details] - Human-readable detail shown in the admin Logs view.
 * @returns {Promise<void>}
 */
async function log(env, username, action, details = "") {
  await env.DB.prepare("INSERT INTO logs (username, action, details) VALUES (?, ?, ?)").bind(username, action, details).run();
}

/**
 * Convert an article title into a URL-safe slug for use in /article/[id]-[slug].
 * Lowercases, strips non-alphanumeric characters (except hyphens), collapses
 * runs of hyphens, and trims leading/trailing hyphens. The article id is
 * always prepended by the caller so collisions between identically-titled
 * articles are impossible.
 * @param {string} title
 * @returns {string}
 */
function slugify(title) {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/[\s-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80); // cap length so URLs stay readable
}

/**
 * Parse a User-Agent string into a coarse device type, browser, and OS
 * label for analytics grouping. Deliberately simple regex matching rather
 * than a full UA-parsing library — good enough to bucket views into
 * meaningful categories on a dashboard without adding a dependency. Order
 * of checks matters (e.g. Edge's UA also contains "Chrome", so Edge must
 * be checked first).
 * @param {string} ua - The raw User-Agent header string.
 * @returns {{deviceType: string, browser: string, os: string}}
 */
function parseUserAgent(ua) {
  const s = ua || "";

  let deviceType = "desktop";
  if (/tablet|ipad/i.test(s)) deviceType = "tablet";
  else if (/mobile|android|iphone/i.test(s)) deviceType = "mobile";

  let browser = "Other";
  if (/edg\//i.test(s)) browser = "Edge";
  else if (/opr\/|opera/i.test(s)) browser = "Opera";
  else if (/chrome\//i.test(s)) browser = "Chrome";
  else if (/firefox\//i.test(s)) browser = "Firefox";
  else if (/safari\//i.test(s) && !/chrome/i.test(s)) browser = "Safari";

  let os = "Other";
  if (/windows/i.test(s)) os = "Windows";
  else if (/mac os|macintosh/i.test(s)) os = "macOS";
  else if (/android/i.test(s)) os = "Android";
  else if (/iphone|ipad|ios/i.test(s)) os = "iOS";
  else if (/linux/i.test(s)) os = "Linux";

  return { deviceType, browser, os };
}

export default {
  /**
   * Single entry point for the whole Worker. Every HTTP request — API calls
   * and static asset requests alike — comes through here. Routes are matched
   * by exact pathname + method against a flat if-chain; the first match wins
   * and returns. Anything that doesn't match an /api/* route falls through
   * to static asset serving at the bottom (the public site + portal HTML/CSS),
   * which also handles clean URLs (e.g. /portal -> portal.html).
   *
   * Route reference (all POST unless noted):
   *  PUBLIC (no auth required)
   *   - POST /api/login                    Authenticate, issue a session token.
   *   - POST /api/logout                   Invalidate the caller's session token.
   *   - GET  /api/articles?category=...    List published articles in a category (public site).
   *   - GET  /api/article-hash?id=...      Lightweight integrity hash for one published article (powers client-side tamper/update detection).
   *   - GET  /api/article/:id-slug         Fetch one published article by its id-slug (e.g. /api/article/1-mayoral-election). Used by the /article/* page renderer.
   *   - GET  /api/auth/discord/login       Redirect to Discord's OAuth2 consent screen.
   *   - GET  /api/auth/discord/callback    Discord redirects here with a code; exchanges it, upserts the reader, issues a session.
   *   - GET  /api/auth/discord/me          Resolve the caller's Discord session, if any.
   *   - GET  /api/comments?article_id=...  List visible comments on an article.
   *   - GET  /api/favorites/check          (used with reader token) which of a set of article IDs the caller has favorited.
   *   - POST /api/analytics/view           Record one article view (called on article open).
   *   - POST /api/analytics/ping           Heartbeat: update read time + scroll depth for an open view.
   *
   *  AUTH'D DISCORD READER (Bearer = discord session token)
   *   - POST /api/auth/discord/logout      Invalidate the caller's Discord session token.
   *   - POST /api/comments                 Post a comment on a published article.
   *   - POST /api/comments/delete          Soft-delete the caller's own comment.
   *   - GET  /api/favorites                List the caller's favorited articles (full objects).
   *   - POST /api/favorites/toggle         Favorite/unfavorite an article.
   *
   *  ANY AUTHENTICATED STAFF USER
   *   - POST /api/articles                 Submit a new article for review (always starts pending_review).
   *   - POST /api/article-detail           Fetch one article's full detail (writers: own only; editors/admins: any).
   *   - POST /api/my-articles              List the caller's own submitted articles + status.
   *   - POST /api/my-articles/resubmit     Resubmit a 'returned' article with revisions.
   *   - POST /api/analytics/article        Full analytics dashboard for one article (writers: own only; editors/admins: any).
   *   - POST /api/analytics/summary        Views summary across the caller's articles (editors/admins can pass site_wide:true or target_username).
   *
   *  EDITOR or ADMIN
   *   - POST /api/articles/instapublish    Publish an article immediately, skipping review.
   *   - POST /api/editor/pending           List the open pending_review queue.
   *   - POST /api/editor/claim             Claim a pending article for review.
   *   - POST /api/editor/my-claims         List articles claimed by the caller.
   *   - POST /api/editor/approve           Approve a claimed/returned article -> published.
   *   - POST /api/editor/return            Return a claimed article to its writer with notes.
   *   - POST /api/editor/deny              Permanently deny a claimed/returned article.
   *
   *  ADMIN ONLY
   *   - POST /api/admin/all-claimed        List every claimed/returned article system-wide.
   *   - POST /api/admin/steal-claim        Reassign any in-progress article to the caller.
   *   - POST /api/admin/articles           List all articles, optionally filtered by status.
   *   - POST /api/admin/edit               Edit a published article's title/content.
   *   - POST /api/admin/censor             Toggle a published article's censored state.
   *   - POST /api/admin/delete             Permanently delete an article.
   *   - POST /api/admin/users              List all user accounts.
   *   - POST /api/admin/user-detail        Fetch one user's profile + article count.
   *   - POST /api/admin/user-history       Fetch one user's full audit-log history.
   *   - POST /api/admin/create-user        Create a new user account.
   *   - POST /api/admin/change-role        Change a user's role (writer/editor/admin).
   *   - POST /api/admin/set-status         Suspend or reactivate a user account.
   *   - POST /api/admin/reset-password     Set a new password for a user.
   *   - POST /api/admin/delete-user        Permanently delete a user account.
   *   - POST /api/admin/logs               Fetch the global audit log.
   *
   *  FALLTHROUGH
   *   - *                                  Serve static assets (HTML/CSS/JS/images) from KV, with clean-URL rewriting.
   *
   * @param {Request} request - The incoming HTTP request.
   * @param {object} env - Worker environment bindings (env.DB is the D1 database, env.__STATIC_CONTENT is the asset bucket).
   * @param {ExecutionContext} ctx - Cloudflare execution context, used to extend the worker's lifetime for async KV asset fetches.
   * @returns {Promise<Response>} The HTTP response for this request.
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Cloudflare sets CF-Connecting-IP on every request; fall back to a
    // request-id derivative so rate limiting still works in local dev.
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";

    // API: Login
    if (url.pathname === "/api/login" && request.method === "POST") {
      pruneRateLimitStore();
      // 10 attempts per IP per minute to slow brute-force without locking out legitimate users.
      if (isRateLimited(`login:${clientIp}`, 10, 60_000)) {
        return secureJson({ success: false, error: "Too many login attempts — try again in a minute." }, { status: 429 });
      }

      const { username, password } = await request.json();
      if (!username || !password) return secureJson({ success: false }, { status: 400 });

      const user = await env.DB.prepare(
        "SELECT * FROM users WHERE username = ?"
      ).bind(username).first();

      const ok = user && user.status === "active" && (await verifyPassword(password, user.password, user.password_salt));

      if (ok) {
        const token = newSessionToken();
        const expiresAt = new Date(Date.now() + 1000 * 60 * 20).toISOString(); // 20min sliding session
        await env.DB.prepare(
          "INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)"
        ).bind(token, user.username, expiresAt).run();
        await env.DB.prepare("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE username = ?").bind(user.username).run();

        await log(env, username, "LOGIN", "Logged into employee portal");
        return secureJson({ success: true, token, user: { username: user.username, role: user.role } });
      }
      await log(env, username, "FAILED_LOGIN", "Failed login attempt");
      return secureJson({ success: false });
    }

    // API: Logout
    if (url.pathname === "/api/logout" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
      if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
      return secureJson({ success: true });
    }

    // ============================================================
    // DISCORD OAUTH2 (public reader login)
    // ============================================================

    // PUBLIC: Kick off Discord OAuth2 — redirect the browser to Discord's
    // consent screen. `state` is a random value stored nowhere server-side;
    // instead we echo it back via redirect and let the client verify it
    // against what it generated before navigating here (CSRF protection
    // without needing server-side state storage for an anonymous visitor).
    if (url.pathname === "/api/auth/discord/login" && request.method === "GET") {
      const state = url.searchParams.get("state") || "";
      const redirectUri = `${url.origin}/api/auth/discord/callback`;
      const discordUrl = new URL("https://discord.com/oauth2/authorize");
      discordUrl.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
      discordUrl.searchParams.set("redirect_uri", redirectUri);
      discordUrl.searchParams.set("response_type", "code");
      discordUrl.searchParams.set("scope", "identify");
      discordUrl.searchParams.set("state", state);
      discordUrl.searchParams.set("prompt", "consent");
      return Response.redirect(discordUrl.toString(), 302);
    }

    // PUBLIC: Discord redirects back here with ?code=...&state=.... Exchange
    // the code for an access token, fetch the user's Discord identity,
    // upsert a discord_users row, issue our own session token, and redirect
    // back to the site with the token + state in the URL fragment (never
    // the query string — fragments aren't sent to the server or logged).
    if (url.pathname === "/api/auth/discord/callback" && request.method === "GET") {
      pruneRateLimitStore();
      if (isRateLimited(`discord_cb:${clientIp}`, 20, 60_000)) {
        return Response.redirect(`${url.origin}/?discord_error=rate_limited`, 302);
      }
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state") || "";
      if (!code) return Response.redirect(`${url.origin}/?discord_error=missing_code`, 302);

      const redirectUri = `${url.origin}/api/auth/discord/callback`;

      let tokenData;
      try {
        const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: env.DISCORD_CLIENT_ID,
            client_secret: env.DISCORD_CLIENT_SECRET,
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
          }).toString(),
        });
        tokenData = await tokenRes.json();
        if (!tokenData.access_token) throw new Error("No access token in response");
      } catch (e) {
        return Response.redirect(`${url.origin}/?discord_error=token_exchange_failed`, 302);
      }

      let discordProfile;
      try {
        const profileRes = await fetch("https://discord.com/api/users/@me", {
          headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        discordProfile = await profileRes.json();
        if (!discordProfile.id) throw new Error("No id in profile response");
      } catch (e) {
        return Response.redirect(`${url.origin}/?discord_error=profile_fetch_failed`, 302);
      }

      const displayName = discordProfile.global_name || discordProfile.username;

      const existing = await env.DB.prepare(
        "SELECT id FROM discord_users WHERE discord_id = ?"
      ).bind(discordProfile.id).first();

      let discordUserId;
      if (existing) {
        discordUserId = existing.id;
        await env.DB.prepare(
          "UPDATE discord_users SET username = ?, avatar_hash = ?, last_login_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(displayName, discordProfile.avatar || null, discordUserId).run();
      } else {
        const inserted = await env.DB.prepare(
          "INSERT INTO discord_users (discord_id, username, avatar_hash, last_login_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
        ).bind(discordProfile.id, displayName, discordProfile.avatar || null).run();
        discordUserId = inserted.meta.last_row_id;
      }

      const banCheck = await env.DB.prepare("SELECT status FROM discord_users WHERE id = ?").bind(discordUserId).first();
      if (banCheck.status !== "active") {
        return Response.redirect(`${url.origin}/?discord_error=banned`, 302);
      }

      const sessionToken = newSessionToken();
      const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(); // 30-day reader session
      await env.DB.prepare(
        "INSERT INTO discord_sessions (token, discord_user_id, expires_at) VALUES (?, ?, ?)"
      ).bind(sessionToken, discordUserId, expiresAt).run();

      const redirectBack = new URL(url.origin + "/");
      redirectBack.hash = `discord_token=${sessionToken}&state=${encodeURIComponent(state)}`;
      return Response.redirect(redirectBack.toString(), 302);
    }

    // PUBLIC (auth'd reader): who am I — used by the front end on page load
    // to restore a logged-in reader's name/avatar from a stored token.
    if (url.pathname === "/api/auth/discord/me" && request.method === "GET") {
      const reader = await getDiscordSessionUser(env, request);
      if (!reader) return secureJson({ loggedIn: false });
      return secureJson({
        loggedIn: true,
        username: reader.username,
        avatarUrl: reader.avatar_hash
          ? `https://cdn.discordapp.com/avatars/${reader.discord_id}/${reader.avatar_hash}.png`
          : null,
      });
    }

    // PUBLIC (auth'd reader): log out
    if (url.pathname === "/api/auth/discord/logout" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
      if (token) await env.DB.prepare("DELETE FROM discord_sessions WHERE token = ?").bind(token).run();
      return secureJson({ success: true });
    }

    // ============================================================
    // COMMENTS
    // ============================================================

    // PUBLIC: list visible comments for an article, oldest first.
    if (url.pathname === "/api/comments" && request.method === "GET") {
      const articleId = url.searchParams.get("article_id");
      if (!articleId) return secureJson({ error: "Missing article_id" }, { status: 400 });

      const results = await env.DB.prepare(
        `SELECT comments.id, comments.content, comments.created_at, discord_users.username, discord_users.avatar_hash, discord_users.discord_id
         FROM comments JOIN discord_users ON comments.discord_user_id = discord_users.id
         WHERE comments.article_id = ? AND comments.status = 'visible'
         ORDER BY comments.created_at ASC`
      ).bind(articleId).all();

      const comments = results.results.map((c) => ({
        id: c.id,
        content: c.content,
        created_at: c.created_at,
        username: c.username,
        avatarUrl: c.avatar_hash ? `https://cdn.discordapp.com/avatars/${c.discord_id}/${c.avatar_hash}.png` : null,
      }));
      return secureJson(comments);
    }

    // AUTH'D READER: post a comment.
    if (url.pathname === "/api/comments" && request.method === "POST") {
      const reader = await getDiscordSessionUser(env, request);
      if (!reader) return secureJson({ error: "Unauthorized" }, { status: 401 });

      // 5 comments per Discord user per minute — prevents spam flooding.
      pruneRateLimitStore();
      if (isRateLimited(`comment:${reader.id}`, 5, 60_000)) {
        return secureJson({ error: "You're posting too fast — please wait a moment." }, { status: 429 });
      }

      const { article_id, content } = await request.json();
      const trimmed = (content || "").trim();
      if (!trimmed) return secureJson({ error: "Comment cannot be empty" }, { status: 400 });
      if (trimmed.length > MAX_COMMENT_LEN) return secureJson({ error: `Comment is too long (${MAX_COMMENT_LEN} character max)` }, { status: 400 });

      const articleIdInt = parseInt(article_id, 10);
      if (!articleIdInt || isNaN(articleIdInt)) return secureJson({ error: "Invalid article" }, { status: 400 });

      const article = await env.DB.prepare("SELECT id FROM articles WHERE id = ? AND status = 'published'").bind(articleIdInt).first();
      if (!article) return secureJson({ error: "Article not found" }, { status: 404 });

      await env.DB.prepare(
        "INSERT INTO comments (article_id, discord_user_id, content) VALUES (?, ?, ?)"
      ).bind(articleIdInt, reader.id, trimmed).run();
      return secureJson({ success: true });
    }

    // AUTH'D READER: delete own comment (soft delete).
    if (url.pathname === "/api/comments/delete" && request.method === "POST") {
      const reader = await getDiscordSessionUser(env, request);
      if (!reader) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const { comment_id } = await request.json();
      const comment = await env.DB.prepare("SELECT discord_user_id FROM comments WHERE id = ?").bind(comment_id).first();
      if (!comment || comment.discord_user_id !== reader.id) {
        return secureJson({ error: "Not found or not yours" }, { status: 404 });
      }

      await env.DB.prepare("UPDATE comments SET status = 'removed' WHERE id = ?").bind(comment_id).run();
      return secureJson({ success: true });
    }

    // ============================================================
    // FAVORITES
    // ============================================================

    // AUTH'D READER: list own favorited articles (full article objects, for
    // rendering the "My Favorites" menu without a second round of lookups).
    if (url.pathname === "/api/favorites" && request.method === "GET") {
      const reader = await getDiscordSessionUser(env, request);
      if (!reader) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const results = await env.DB.prepare(
        `SELECT articles.id, articles.title, articles.category, articles.author, articles.created_at, favorites.created_at as favorited_at
         FROM favorites JOIN articles ON favorites.article_id = articles.id
         WHERE favorites.discord_user_id = ? AND articles.status = 'published'
         ORDER BY favorites.created_at DESC`
      ).bind(reader.id).all();
      return secureJson(results.results);
    }

    // AUTH'D READER: toggle favorite status for an article (favorite if not
    // already, unfavorite if already favorited). Returns the resulting state
    // so the client can flip its heart icon without a separate GET.
    if (url.pathname === "/api/favorites/toggle" && request.method === "POST") {
      const reader = await getDiscordSessionUser(env, request);
      if (!reader) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const { article_id } = await request.json();
      const existing = await env.DB.prepare(
        "SELECT id FROM favorites WHERE discord_user_id = ? AND article_id = ?"
      ).bind(reader.id, article_id).first();

      if (existing) {
        await env.DB.prepare("DELETE FROM favorites WHERE id = ?").bind(existing.id).run();
        return secureJson({ favorited: false });
      } else {
        await env.DB.prepare(
          "INSERT INTO favorites (discord_user_id, article_id) VALUES (?, ?)"
        ).bind(reader.id, article_id).run();
        return secureJson({ favorited: true });
      }
    }

    // PUBLIC (auth'd reader): which of a given set of article IDs has the
    // caller favorited — used to paint hearts correctly on page load across
    // a whole category grid in one call instead of one round-trip per card.
    if (url.pathname === "/api/favorites/check" && request.method === "POST") {
      const reader = await getDiscordSessionUser(env, request);
      if (!reader) return secureJson({ favorited: [] });

      const { article_ids } = await request.json();
      if (!Array.isArray(article_ids) || article_ids.length === 0) return secureJson({ favorited: [] });

      const placeholders = article_ids.map(() => "?").join(",");
      const results = await env.DB.prepare(
        `SELECT article_id FROM favorites WHERE discord_user_id = ? AND article_id IN (${placeholders})`
      ).bind(reader.id, ...article_ids).all();
      return secureJson({ favorited: results.results.map((r) => r.article_id) });
    }

    // ============================================================
    // ANALYTICS (view tracking, writer dashboard)
    // ============================================================

    // PUBLIC: record one article view. Called once when an article modal
    // opens. device/browser/os are parsed server-side from the UA string
    // (kept out of the client so the parsing logic lives in one place and
    // can't be tampered with from devtools the way a client-computed label
    // could be).
    if (url.pathname === "/api/analytics/view" && request.method === "POST") {
      const { article_id, visitor_id, referrer } = await request.json();
      if (!article_id || !visitor_id) return secureJson({ error: "Missing fields" }, { status: 400 });

      const article = await env.DB.prepare("SELECT id FROM articles WHERE id = ?").bind(article_id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });

      const ua = request.headers.get("User-Agent") || "";
      const { deviceType, browser, os } = parseUserAgent(ua);

      let referrerDomain = null;
      if (referrer) {
        try { referrerDomain = new URL(referrer).hostname; } catch (e) { referrerDomain = null; }
      }

      const reader = await getDiscordSessionUser(env, request);

      const inserted = await env.DB.prepare(
        `INSERT INTO page_views (article_id, visitor_id, referrer, referrer_domain, user_agent, device_type, browser, os, is_discord_user)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(article_id, visitor_id, referrer || "", referrerDomain, ua, deviceType, browser, os, reader ? 1 : 0).run();

      return secureJson({ success: true, view_id: inserted.meta.last_row_id });
    }

    // PUBLIC: heartbeat ping while an article stays open, updating read time
    // and max scroll depth for the view row created by /api/analytics/view.
    // Client sends this every ~10s while the modal is open and the tab is
    // visible (paused on tab-blur) so read_seconds reflects actual attention,
    // not just "tab was open in the background".
    if (url.pathname === "/api/analytics/ping" && request.method === "POST") {
      const { view_id, read_seconds, max_scroll_pct } = await request.json();
      if (!view_id) return secureJson({ error: "Missing view_id" }, { status: 400 });

      await env.DB.prepare(
        "UPDATE page_views SET read_seconds = ?, max_scroll_pct = ? WHERE id = ?"
      ).bind(read_seconds || 0, max_scroll_pct || 0, view_id).run();
      return secureJson({ success: true });
    }

    // AUTH'D (any staff): full analytics dashboard for one article. Writers
    // may only request their own articles; editors/admins may request any.
    // Returns a comprehensive bundle in one call (totals, a daily
    // time series, referrer/device/browser/os breakdowns, and read-depth
    // stats) so the dashboard renders from a single round trip.
    if (url.pathname === "/api/analytics/article" && request.method === "POST") {
      const user = await getSessionUser(env, request);
      if (!user) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const { article_id } = await request.json();
      const article = await env.DB.prepare("SELECT id, title, author FROM articles WHERE id = ?").bind(article_id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });
      if (article.author !== user.username && user.role !== "editor" && user.role !== "admin") {
        return secureJson({ error: "Unauthorized" }, { status: 403 });
      }

      const totals = await env.DB.prepare(
        `SELECT COUNT(*) as total_views, COUNT(DISTINCT visitor_id) as unique_visitors,
                AVG(read_seconds) as avg_read_seconds, AVG(max_scroll_pct) as avg_scroll_pct,
                SUM(is_discord_user) as discord_views
         FROM page_views WHERE article_id = ?`
      ).bind(article_id).first();

      const dailySeries = await env.DB.prepare(
        `SELECT DATE(created_at) as day, COUNT(*) as views, COUNT(DISTINCT visitor_id) as unique_visitors
         FROM page_views WHERE article_id = ? GROUP BY DATE(created_at) ORDER BY day ASC`
      ).bind(article_id).all();

      const referrers = await env.DB.prepare(
        `SELECT COALESCE(NULLIF(referrer_domain, ''), 'Direct / Unknown') as source, COUNT(*) as views
         FROM page_views WHERE article_id = ? GROUP BY source ORDER BY views DESC LIMIT 15`
      ).bind(article_id).all();

      const devices = await env.DB.prepare(
        `SELECT device_type, COUNT(*) as views FROM page_views WHERE article_id = ? GROUP BY device_type ORDER BY views DESC`
      ).bind(article_id).all();

      const browsers = await env.DB.prepare(
        `SELECT browser, COUNT(*) as views FROM page_views WHERE article_id = ? GROUP BY browser ORDER BY views DESC`
      ).bind(article_id).all();

      const osBreakdown = await env.DB.prepare(
        `SELECT os, COUNT(*) as views FROM page_views WHERE article_id = ? GROUP BY os ORDER BY views DESC`
      ).bind(article_id).all();

      const readDepthBuckets = await env.DB.prepare(
        `SELECT
           SUM(CASE WHEN max_scroll_pct < 25 THEN 1 ELSE 0 END) as bucket_0_25,
           SUM(CASE WHEN max_scroll_pct >= 25 AND max_scroll_pct < 50 THEN 1 ELSE 0 END) as bucket_25_50,
           SUM(CASE WHEN max_scroll_pct >= 50 AND max_scroll_pct < 75 THEN 1 ELSE 0 END) as bucket_50_75,
           SUM(CASE WHEN max_scroll_pct >= 75 THEN 1 ELSE 0 END) as bucket_75_100
         FROM page_views WHERE article_id = ?`
      ).bind(article_id).first();

      return secureJson({
        article: { id: article.id, title: article.title },
        totals: {
          total_views: totals.total_views || 0,
          unique_visitors: totals.unique_visitors || 0,
          avg_read_seconds: Math.round(totals.avg_read_seconds || 0),
          avg_scroll_pct: Math.round(totals.avg_scroll_pct || 0),
          discord_views: totals.discord_views || 0,
        },
        daily_series: dailySeries.results,
        referrers: referrers.results,
        devices: devices.results,
        browsers: browsers.results,
        os: osBreakdown.results,
        read_depth: readDepthBuckets,
      });
    }

    // AUTH'D (any staff): summary analytics across ALL of the caller's
    // articles (writers see only their own; editors/admins can pass
    // target_username to inspect someone else's, or omit it for site-wide).
    // Powers a "My Articles" overview table sorted by views.
    if (url.pathname === "/api/analytics/summary" && request.method === "POST") {
      const user = await getSessionUser(env, request);
      if (!user) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const body = await request.json().catch(() => ({}));
      let targetUsername = user.username;
      if (body.target_username && (user.role === "editor" || user.role === "admin")) {
        targetUsername = body.target_username; // null/omitted handled by site-wide branch below
      }

      const siteWide = (user.role === "editor" || user.role === "admin") && body.site_wide === true;

      const query = siteWide
        ? `SELECT articles.id, articles.title, articles.category, articles.author, articles.created_at,
                  COUNT(page_views.id) as total_views, COUNT(DISTINCT page_views.visitor_id) as unique_visitors,
                  AVG(page_views.read_seconds) as avg_read_seconds
           FROM articles LEFT JOIN page_views ON page_views.article_id = articles.id
           WHERE articles.status = 'published'
           GROUP BY articles.id ORDER BY total_views DESC`
        : `SELECT articles.id, articles.title, articles.category, articles.author, articles.created_at,
                  COUNT(page_views.id) as total_views, COUNT(DISTINCT page_views.visitor_id) as unique_visitors,
                  AVG(page_views.read_seconds) as avg_read_seconds
           FROM articles LEFT JOIN page_views ON page_views.article_id = articles.id
           WHERE articles.status = 'published' AND articles.author = ?
           GROUP BY articles.id ORDER BY total_views DESC`;

      const results = siteWide
        ? await env.DB.prepare(query).all()
        : await env.DB.prepare(query).bind(targetUsername).all();

      const rows = results.results.map((r) => ({
        ...r,
        avg_read_seconds: Math.round(r.avg_read_seconds || 0),
      }));
      return secureJson(rows);
    }

    // API: Submit article (writers, editors, admins all submit through here)
    // New articles always start as pending_review — nobody publishes directly
    // through this route, regardless of role. Editors/admins who want to skip

    // review use /api/articles/instapublish instead.
    if (url.pathname === "/api/articles" && request.method === "POST") {
      const user = await getSessionUser(env, request);
      if (!user) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const { title, category, content, image_url: imageUrlRaw } = await request.json();
      if (!title || !title.trim()) return secureJson({ error: "Title is required." }, { status: 400 });
      if (!content || !content.trim()) return secureJson({ error: "Content is required." }, { status: 400 });
      if (!VALID_CATEGORIES.has(category)) return secureJson({ error: "Invalid category." }, { status: 400 });
      if (title.trim().length > MAX_TITLE_LEN) return secureJson({ error: `Title must be under ${MAX_TITLE_LEN} characters.` }, { status: 400 });
      if (content.trim().length > MAX_CONTENT_LEN) return secureJson({ error: `Content must be under ${MAX_CONTENT_LEN} characters.` }, { status: 400 });
      const imageUrl = validateImageUrl(imageUrlRaw);
      if (imageUrlRaw && !imageUrl) return secureJson({ error: "Invalid or oversized image (max ~600 KB, JPEG/PNG/WebP/GIF only)." }, { status: 400 });

      await env.DB.prepare(
        "INSERT INTO articles (title, category, content, author, status, image_url) VALUES (?, ?, ?, ?, 'pending_review', ?)"
      ).bind(title.trim(), category, content.trim(), user.username, imageUrl).run();
      await log(env, user.username, "POST_ARTICLE", `Submitted article "${title.trim()}" in category "${category}" for review`);
      return secureJson({ success: true });
    }

    // EDITOR/ADMIN: publish an article immediately, skipping the review pipeline
    // entirely (no pending_review/claimed row is ever created). Logged distinctly
    // so it's clear in the audit trail that it bypassed review.
    if (url.pathname === "/api/articles/instapublish" && request.method === "POST") {
      const user = await requireEditorOrAdmin(env, request);
      if (!user) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { title, category, content, image_url: imageUrlRaw } = await request.json();
      if (!title || !content || !category) {
        return secureJson({ error: "Title, category, and content are all required." }, { status: 400 });
      }
      if (!VALID_CATEGORIES.has(category)) return secureJson({ error: "Invalid category." }, { status: 400 });
      if (title.trim().length > MAX_TITLE_LEN) return secureJson({ error: `Title must be under ${MAX_TITLE_LEN} characters.` }, { status: 400 });
      if (content.trim().length > MAX_CONTENT_LEN) return secureJson({ error: `Content must be under ${MAX_CONTENT_LEN} characters.` }, { status: 400 });
      const imageUrl = validateImageUrl(imageUrlRaw);
      if (imageUrlRaw && !imageUrl) return secureJson({ error: "Invalid or oversized image (max ~600 KB, JPEG/PNG/WebP/GIF only)." }, { status: 400 });

      await env.DB.prepare(
        "INSERT INTO articles (title, category, content, author, status, image_url) VALUES (?, ?, ?, ?, 'published', ?)"
      ).bind(title.trim(), category, content.trim(), user.username, imageUrl).run();
      await log(env, user.username, "INSTAPUBLISH_ARTICLE", `Published article "${title.trim()}" in category "${category}" directly, bypassing review`);
      return secureJson({ success: true });
    }

    // API: Get published articles by category (public-facing pages)
    if (url.pathname === "/api/articles" && request.method === "GET") {
      const category = url.searchParams.get("category");
      if (!VALID_CATEGORIES.has(category)) return secureJson([], { status: 200 });

      const results = await env.DB.prepare(
        "SELECT * FROM articles WHERE category = ? AND status = 'published' ORDER BY created_at DESC"
      ).bind(category).all();

      // Attach a computed slug to each article so the front end can build
      // /article/[id]-[slug] links without a separate lookup.
      const articles = results.results.map(a => ({
        ...a,
        slug: `${a.id}-${slugify(a.title)}`,
      }));
      return secureJson(articles);
    }

    // PUBLIC: fetch ALL published articles across every category, newest first.
    if (url.pathname === "/api/articles/all" && request.method === "GET") {
      pruneRateLimitStore();
      if (isRateLimited(`articles_all:${clientIp}`, 30, 60_000)) {
        return secureJson({ error: "Too many requests" }, { status: 429 });
      }
      const results = await env.DB.prepare(
        "SELECT * FROM articles WHERE status = 'published' ORDER BY created_at DESC"
      ).all();
      const articles = results.results.map(a => ({
        ...a,
        slug: `${a.id}-${slugify(a.title)}`,
      }));
      return secureJson(articles);
    }

    // PUBLIC: fetch one published article by its id-slug for the /article/* page.
    // The slug format is [id]-[title-slug] (e.g. "1-mayoral-election-results").
    // We parse the numeric id from the front of the param, look up by id, then
    // verify the article is published — the slug portion is cosmetic/readable
    // but not used for the lookup (so renamed articles keep their old URLs
    // working as long as the id prefix is still present).
    if (url.pathname.startsWith("/api/article/") && request.method === "GET") {
      const param = url.pathname.slice("/api/article/".length);
      const id = parseInt(param.split("-")[0], 10);
      if (!id || isNaN(id)) return secureJson({ error: "Not found" }, { status: 404 });

      const article = await env.DB.prepare(
        "SELECT * FROM articles WHERE id = ? AND status = 'published'"
      ).bind(id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });

      return secureJson({ ...article, slug: `${article.id}-${slugify(article.title)}` });
    }

    // API: Lightweight integrity check for an open article (public, no auth).
    // Returns a SHA-256 hash of the article's current title+content so a
    // reader's open tab can detect — without re-downloading the full body —
    // whether the published article changed (edited/censored/deleted) while
    // they were reading it. Polled client-side every few seconds from the
    // article modal; cheap enough on D1 to call frequently.
    if (url.pathname === "/api/article-hash" && request.method === "GET") {
      const id = url.searchParams.get("id");
      if (!id) return secureJson({ error: "Missing id" }, { status: 400 });

      const article = await env.DB.prepare(
        "SELECT title, content FROM articles WHERE id = ? AND status = 'published'"
      ).bind(id).first();

      // Article was deleted, censored, or never existed — tell the client
      // explicitly rather than letting a hash mismatch imply "edited".
      if (!article) return secureJson({ exists: false });

      const hash = await hashArticleText(article.title, article.content);
      return secureJson({ exists: true, hash });
    }

    // ---------------- SHARED: article detail (powers the click-to-expand overlay) ----------------

    // Any authenticated user: fetch one article's full detail. Writers may only
    // view their own articles this way; editors/admins may view any article.
    // This route itself grants no new permissions — every action button the
    // frontend shows still re-validates against its own route exactly as before.
    if (url.pathname === "/api/article-detail" && request.method === "POST") {
      const user = await getSessionUser(env, request);
      if (!user) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const { id } = await request.json();
      const article = await env.DB.prepare("SELECT * FROM articles WHERE id = ?").bind(id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });

      const isPrivileged = user.role === "editor" || user.role === "admin";
      if (!isPrivileged && article.author !== user.username) {
        return secureJson({ error: "Unauthorized" }, { status: 403 });
      }

      return secureJson(article);
    }

    // ---------------- WRITER: "My Articles" ----------------

    // WRITER: list the logged-in user's own submissions + status.
    // Read-only by design — editing only happens via /api/my-articles/resubmit
    // on articles that are in the 'returned' state.
    if (url.pathname === "/api/my-articles" && request.method === "POST") {
      const user = await getSessionUser(env, request);
      if (!user) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const results = await env.DB.prepare(
        "SELECT id, title, category, content, status, claimed_by, review_notes, created_at, updated_at FROM articles WHERE author = ? ORDER BY updated_at DESC"
      ).bind(user.username).all();
      return secureJson(results.results);
    }

    // WRITER: resubmit a 'returned' article with revised content.
    // Goes straight back to 'claimed' under the SAME editor who returned it —
    // it does not re-enter the open pending_review pool.
    if (url.pathname === "/api/my-articles/resubmit" && request.method === "POST") {
      const user = await getSessionUser(env, request);
      if (!user) return secureJson({ error: "Unauthorized" }, { status: 401 });

      const { id, title, content, image_url: imageUrlRaw, remove_image } = await request.json();
      const article = await env.DB.prepare(
        "SELECT * FROM articles WHERE id = ? AND author = ?"
      ).bind(id, user.username).first();

      if (!article) return secureJson({ error: "Not found" }, { status: 404 });
      if (article.status !== "returned") {
        return secureJson({ error: "This article isn't awaiting revision." }, { status: 400 });
      }

      let imageUpdateSql = "";
      let imageUpdateVal = undefined;
      if (remove_image) {
        imageUpdateSql = ", image_url = NULL";
      } else if (imageUrlRaw !== undefined) {
        const imageUrl = validateImageUrl(imageUrlRaw);
        if (imageUrlRaw && !imageUrl) return secureJson({ error: "Invalid or oversized image." }, { status: 400 });
        imageUpdateSql = ", image_url = ?";
        imageUpdateVal = imageUrl;
      }

      const resubSql = `UPDATE articles SET title = ?, content = ?${imageUpdateSql}, status = 'claimed', review_notes = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
      const resubBinds = imageUpdateVal !== undefined ? [title, content, imageUpdateVal, id] : [title, content, id];
      await env.DB.prepare(resubSql).bind(...resubBinds).run();
      await log(env, user.username, "RESUBMIT_ARTICLE", `Resubmitted article "${title}" (ID ${id}) to ${article.claimed_by} after revision`);
      return secureJson({ success: true });
    }

    // ---------------- EDITOR (and admin): review queue ----------------

    // EDITOR/ADMIN: pending_review queue (open pool, nothing claimed yet)
    if (url.pathname === "/api/editor/pending" && request.method === "POST") {
      const reviewer = await requireEditorOrAdmin(env, request);
      if (!reviewer) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const results = await env.DB.prepare(
        "SELECT id, title, category, author, status, created_at FROM articles WHERE status = 'pending_review' ORDER BY created_at ASC"
      ).all();
      return secureJson(results.results);
    }

    // EDITOR/ADMIN: claim a pending article. Once claimed, it disappears from
    // other editors' pending queue, but admins still see it (with claimed_by shown).
    if (url.pathname === "/api/editor/claim" && request.method === "POST") {
      const reviewer = await requireEditorOrAdmin(env, request);
      if (!reviewer) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { id } = await request.json();
      const article = await env.DB.prepare("SELECT * FROM articles WHERE id = ?").bind(id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });
      if (article.status !== "pending_review") {
        return secureJson({ error: "This article has already been claimed or is no longer pending." }, { status: 409 });
      }

      await env.DB.prepare(
        "UPDATE articles SET status = 'claimed', claimed_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind(reviewer.username, id).run();
      await log(env, reviewer.username, "CLAIM_ARTICLE", `Claimed article "${article.title}" (ID ${id}) for review`);
      return secureJson({ success: true });
    }

    // EDITOR/ADMIN: "My Review Box" — articles claimed by the logged-in reviewer
    // (includes ones returned-and-not-yet-resubmitted, since they stay claimed).
    if (url.pathname === "/api/editor/my-claims" && request.method === "POST") {
      const reviewer = await requireEditorOrAdmin(env, request);
      if (!reviewer) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const results = await env.DB.prepare(
        "SELECT id, title, category, author, content, status, review_notes, created_at, updated_at FROM articles WHERE claimed_by = ? AND status IN ('claimed', 'returned') ORDER BY updated_at DESC"
      ).bind(reviewer.username).all();
      return secureJson(results.results);
    }

    // ADMIN-ONLY: full view of every claimed/in-progress article across all editors,
    // each tagged with who has it ("under review by ___"). Editors only see their own
    // claims via /api/editor/my-claims; this route is for admin oversight.
    // Includes full content so the admin can act (approve/return/deny) without
    // needing to claim it first.
    if (url.pathname === "/api/admin/all-claimed" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const results = await env.DB.prepare(
        "SELECT id, title, category, author, content, status, claimed_by, review_notes, created_at, updated_at FROM articles WHERE status IN ('claimed', 'returned') ORDER BY updated_at DESC"
      ).all();
      return secureJson(results.results);
    }

    // ADMIN-ONLY: take over ("steal") any in-progress article, regardless of who
    // currently has it claimed — or claim straight out of the open pending pool.
    // Reassigns claimed_by to the admin. Logged as a distinct action so it's
    // visible in the audit trail that it was taken from another reviewer.
    if (url.pathname === "/api/admin/steal-claim" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { id } = await request.json();
      const article = await env.DB.prepare("SELECT * FROM articles WHERE id = ?").bind(id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });
      if (!["pending_review", "claimed", "returned"].includes(article.status)) {
        return secureJson({ error: "This article isn't in a reviewable state." }, { status: 400 });
      }

      const previousOwner = article.claimed_by; // null if it was still in the open pool
      const newStatus = article.status === "pending_review" ? "claimed" : article.status;

      await env.DB.prepare(
        "UPDATE articles SET status = ?, claimed_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind(newStatus, admin.username, id).run();

      await log(
        env,
        admin.username,
        "ADMIN_REASSIGN_CLAIM",
        previousOwner
          ? `Took over article "${article.title}" (ID ${id}) from ${previousOwner}`
          : `Claimed article "${article.title}" (ID ${id}) directly from the pending pool`
      );
      return secureJson({ success: true });
    }

    // EDITOR/ADMIN: approve a claimed (or, for admins, returned) article -> published
    if (url.pathname === "/api/editor/approve" && request.method === "POST") {
      const reviewer = await requireEditorOrAdmin(env, request);
      if (!reviewer) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { id } = await request.json();
      const article = await env.DB.prepare("SELECT * FROM articles WHERE id = ?").bind(id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });

      // Editors may only act on their own 'claimed' articles. Admins may also act
      // directly on a 'returned' article (bypassing the writer's revision step)
      // and on anyone's claim, not just their own.
      const adminCanAct = reviewer.role === "admin" && (article.status === "claimed" || article.status === "returned");
      const editorCanAct = reviewer.role !== "admin" && article.status === "claimed" && article.claimed_by === reviewer.username;
      if (!adminCanAct && !editorCanAct) {
        if (article.status !== "claimed" && article.status !== "returned") {
          return secureJson({ error: "Only claimed or returned articles can be approved." }, { status: 400 });
        }
        return secureJson({ error: "This article is claimed by another editor." }, { status: 403 });
      }

      await env.DB.prepare(
        "UPDATE articles SET status = 'published', reviewed_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind(reviewer.username, id).run();
      await log(env, reviewer.username, "APPROVE_ARTICLE", `Approved and published article "${article.title}" (ID ${id}) by ${article.author}`);
      return secureJson({ success: true });
    }

    // EDITOR/ADMIN: return a claimed article to the writer with instructions.
    // Stays claimed by the same reviewer.
    if (url.pathname === "/api/editor/return" && request.method === "POST") {
      const reviewer = await requireEditorOrAdmin(env, request);
      if (!reviewer) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { id, notes } = await request.json();
      if (!notes || !notes.trim()) {
        return secureJson({ error: "Instructions are required when returning an article." }, { status: 400 });
      }

      const article = await env.DB.prepare("SELECT * FROM articles WHERE id = ?").bind(id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });
      if (article.status !== "claimed") {
        return secureJson({ error: "Only claimed articles can be returned." }, { status: 400 });
      }
      if (reviewer.role !== "admin" && article.claimed_by !== reviewer.username) {
        return secureJson({ error: "This article is claimed by another editor." }, { status: 403 });
      }

      // Admins keep the existing claimed_by as-is unless they've already stolen the
      // claim via /api/admin/steal-claim; returning doesn't itself reassign ownership.
      await env.DB.prepare(
        "UPDATE articles SET status = 'returned', review_notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind(notes, id).run();
      await log(env, reviewer.username, "RETURN_ARTICLE", `Returned article "${article.title}" (ID ${id}) to ${article.author} with revision notes`);
      return secureJson({ success: true });
    }

    // EDITOR/ADMIN: deny a claimed (or, for admins, returned) article. Permanent —
    // kept in DB, writer can see why.
    if (url.pathname === "/api/editor/deny" && request.method === "POST") {
      const reviewer = await requireEditorOrAdmin(env, request);
      if (!reviewer) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { id, notes } = await request.json();
      const article = await env.DB.prepare("SELECT * FROM articles WHERE id = ?").bind(id).first();
      if (!article) return secureJson({ error: "Not found" }, { status: 404 });

      const adminCanAct = reviewer.role === "admin" && (article.status === "claimed" || article.status === "returned");
      const editorCanAct = reviewer.role !== "admin" && article.status === "claimed" && article.claimed_by === reviewer.username;
      if (!adminCanAct && !editorCanAct) {
        if (article.status !== "claimed" && article.status !== "returned") {
          return secureJson({ error: "Only claimed or returned articles can be denied." }, { status: 400 });
        }
        return secureJson({ error: "This article is claimed by another editor." }, { status: 403 });
      }

      await env.DB.prepare(
        "UPDATE articles SET status = 'denied', review_notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind(notes || null, id).run();
      await log(env, reviewer.username, "DENY_ARTICLE", `Denied article "${article.title}" (ID ${id}) by ${article.author}`);
      return secureJson({ success: true });
    }

    // ---------------- ADMIN: published-article moderation (unchanged) ----------------

    // ADMIN: Get all articles (any status)
    if (url.pathname === "/api/admin/articles" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { filter } = await request.json();
      let query = "SELECT * FROM articles ORDER BY created_at DESC";
      if (filter === "censored") query = "SELECT * FROM articles WHERE status = 'censored' ORDER BY created_at DESC";
      if (filter === "published") query = "SELECT * FROM articles WHERE status = 'published' ORDER BY created_at DESC";

      const results = await env.DB.prepare(query).all();
      return secureJson(results.results);
    }

    // ADMIN: Edit article
    if (url.pathname === "/api/admin/edit" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { id, title, content, image_url: imageUrlRaw, remove_image } = await request.json();
      if (!title || !title.trim()) return secureJson({ error: "Title is required." }, { status: 400 });
      if (!content || !content.trim()) return secureJson({ error: "Content is required." }, { status: 400 });
      if (title.trim().length > MAX_TITLE_LEN) return secureJson({ error: `Title must be under ${MAX_TITLE_LEN} characters.` }, { status: 400 });
      if (content.trim().length > MAX_CONTENT_LEN) return secureJson({ error: `Content must be under ${MAX_CONTENT_LEN} characters.` }, { status: 400 });

      // image_url: pass a new data URL to replace, pass remove_image:true to clear, omit both to leave as-is
      let imageUpdateSql = "";
      let imageUpdateVal = undefined;
      if (remove_image) {
        imageUpdateSql = ", image_url = NULL";
      } else if (imageUrlRaw !== undefined) {
        const imageUrl = validateImageUrl(imageUrlRaw);
        if (imageUrlRaw && !imageUrl) return secureJson({ error: "Invalid or oversized image." }, { status: 400 });
        imageUpdateSql = ", image_url = ?";
        imageUpdateVal = imageUrl;
      }

      const sql = `UPDATE articles SET title = ?, content = ?${imageUpdateSql}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
      const binds = imageUpdateVal !== undefined
        ? [title.trim(), content.trim(), imageUpdateVal, id]
        : [title.trim(), content.trim(), id];
      await env.DB.prepare(sql).bind(...binds).run();
      await log(env, admin.username, "EDIT_ARTICLE", `Edited article ID ${id} — new title: "${title.trim()}"`);
      return secureJson({ success: true });
    }

    // ADMIN: Censor/uncensor a PUBLISHED article (post-publish takedown — separate from the review pipeline)
    if (url.pathname === "/api/admin/censor" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { id } = await request.json();
      const article = await env.DB.prepare("SELECT status FROM articles WHERE id = ?").bind(id).first();
      const newStatus = article.status === "censored" ? "published" : "censored";
      await env.DB.prepare("UPDATE articles SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(newStatus, id).run();
      await log(env, admin.username, newStatus === "censored" ? "CENSOR_ARTICLE" : "UNCENSOR_ARTICLE", `Article ID ${id} set to ${newStatus}`);
      return secureJson({ success: true });
    }

    // ADMIN: Delete article
    if (url.pathname === "/api/admin/delete" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { id } = await request.json();
      const article = await env.DB.prepare("SELECT title FROM articles WHERE id = ?").bind(id).first();
      // Delete child rows first to satisfy foreign-key constraints
      // (comments, favorites, page_views all REFERENCE articles(id))
      await env.DB.prepare("DELETE FROM comments WHERE article_id = ?").bind(id).run();
      await env.DB.prepare("DELETE FROM favorites WHERE article_id = ?").bind(id).run();
      await env.DB.prepare("DELETE FROM page_views WHERE article_id = ?").bind(id).run();
      await env.DB.prepare("DELETE FROM articles WHERE id = ?").bind(id).run();
      await log(env, admin.username, "DELETE_ARTICLE", `Deleted article ID ${id} — "${article?.title}"`);
      return secureJson({ success: true });
    }

    // ---------------- ADMIN: user management (unchanged) ----------------

    // ADMIN: Get all users
    if (url.pathname === "/api/admin/users" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const results = await env.DB.prepare(
        "SELECT id, username, role, status, created_at, last_login_at FROM users ORDER BY role ASC"
      ).all();
      return secureJson(results.results);
    }

    // ADMIN: Get single user's full (non-credential) profile
    if (url.pathname === "/api/admin/user-detail" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { targetId } = await request.json();
      const target = await env.DB.prepare(
        "SELECT id, username, role, status, created_at, last_login_at FROM users WHERE id = ?"
      ).bind(targetId).first();
      if (!target) return secureJson({ error: "Not found" }, { status: 404 });

      const articleCount = await env.DB.prepare(
        "SELECT COUNT(*) as count FROM articles WHERE author = ?"
      ).bind(target.username).first();

      return secureJson({ ...target, article_count: articleCount.count });
    }

    // ADMIN: Get a single user's complete action history
    if (url.pathname === "/api/admin/user-history" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { targetId } = await request.json();
      const target = await env.DB.prepare("SELECT username FROM users WHERE id = ?").bind(targetId).first();
      if (!target) return secureJson({ error: "Not found" }, { status: 404 });

      const results = await env.DB.prepare(
        "SELECT id, action, details, created_at FROM logs WHERE username = ? ORDER BY created_at DESC LIMIT 500"
      ).bind(target.username).all();
      return secureJson(results.results);
    }

    // ADMIN: Create user
    if (url.pathname === "/api/admin/create-user" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { newUsername, newPassword, role } = await request.json();
      if (!newUsername || !newUsername.trim()) return secureJson({ error: "Username is required." }, { status: 400 });
      if (!newPassword || newPassword.length < 8) return secureJson({ error: "Password must be at least 8 characters." }, { status: 400 });
      if (!["writer", "editor", "admin"].includes(role)) return secureJson({ error: "Invalid role." }, { status: 400 });
      if (newUsername.trim().length > 64) return secureJson({ error: "Username too long." }, { status: 400 });

      const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(newUsername.trim()).first();
      if (existing) return secureJson({ error: "Username already exists" });

      const { hash, salt } = await hashPassword(newPassword);
      await env.DB.prepare(
        "INSERT INTO users (username, password, password_salt, role, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)"
      ).bind(newUsername.trim(), hash, salt, role).run();
      await log(env, admin.username, "CREATE_USER", `Created user "${newUsername.trim()}" with role "${role}"`);
      return secureJson({ success: true });
    }

    // ADMIN: Change user role (writer | editor | admin)
    if (url.pathname === "/api/admin/change-role" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { targetId, role } = await request.json();
      if (!["writer", "editor", "admin"].includes(role)) {
        return secureJson({ error: "Invalid role" }, { status: 400 });
      }

      const target = await env.DB.prepare("SELECT username FROM users WHERE id = ?").bind(targetId).first();
      await env.DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(role, targetId).run();
      await log(env, admin.username, "CHANGE_ROLE", `Changed role of "${target?.username}" to "${role}"`);
      return secureJson({ success: true });
    }

    // ADMIN: Suspend / reactivate user
    if (url.pathname === "/api/admin/set-status" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { targetId, status } = await request.json();
      if (!["active", "suspended"].includes(status)) return secureJson({ error: "Invalid status" }, { status: 400 });

      const target = await env.DB.prepare("SELECT username FROM users WHERE id = ?").bind(targetId).first();
      await env.DB.prepare("UPDATE users SET status = ? WHERE id = ?").bind(status, targetId).run();
      if (status === "suspended" && target) {
        await env.DB.prepare("DELETE FROM sessions WHERE username = ?").bind(target.username).run();
      }
      await log(env, admin.username, "SET_USER_STATUS", `Set status of "${target?.username}" to "${status}"`);
      return secureJson({ success: true });
    }

    // ADMIN: Reset a user's password (admin sets a new one; old one is never shown)
    if (url.pathname === "/api/admin/reset-password" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { targetId, newPassword } = await request.json();
      const target = await env.DB.prepare("SELECT username FROM users WHERE id = ?").bind(targetId).first();
      if (!target) return secureJson({ error: "Not found" }, { status: 404 });

      const { hash, salt } = await hashPassword(newPassword);
      await env.DB.prepare("UPDATE users SET password = ?, password_salt = ? WHERE id = ?").bind(hash, salt, targetId).run();
      await env.DB.prepare("DELETE FROM sessions WHERE username = ?").bind(target.username).run();
      await log(env, admin.username, "RESET_PASSWORD", `Reset password for "${target.username}"`);
      return secureJson({ success: true });
    }

    // ADMIN: Delete user
    if (url.pathname === "/api/admin/delete-user" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const { targetId } = await request.json();
      const target = await env.DB.prepare("SELECT username FROM users WHERE id = ?").bind(targetId).first();
      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(targetId).run();
      if (target) await env.DB.prepare("DELETE FROM sessions WHERE username = ?").bind(target.username).run();
      await log(env, admin.username, "DELETE_USER", `Deleted user "${target?.username}"`);
      return secureJson({ success: true });
    }

    // ADMIN: Get logs (global)
    if (url.pathname === "/api/admin/logs" && request.method === "POST") {
      const admin = await requireAdmin(env, request);
      if (!admin) return secureJson({ error: "Unauthorized" }, { status: 403 });

      const results = await env.DB.prepare("SELECT * FROM logs ORDER BY created_at DESC LIMIT 500").all();
      return secureJson(results.results);
    }

    // Serve static files
    //
    // ================================================================
    // AD SYSTEM — Step 1 routes
    // ================================================================

    // ================================================================
    // PAYMENT MODULE — DC Economy webhook-based payment verification
    // ================================================================
    //
    // Flow:
    //   1. Cron awards winner → sets payment_status = 'awaiting_payment'
    //   2. Staff notifies advertiser (Discord) with their bid ID & amount
    //   3. Advertiser pays your firm account in-game with memo = "bid:<id>"
    //   4. DC Economy POSTs to POST /api/ads/webhook/payment
    //   5. Worker verifies HMAC, parses memo, matches bid, marks paid
    //
    // Setup (one-time):
    //   a. In Minecraft: /treasuryapi business issue <YourFirmName>  → copy token
    //   b. Set Cloudflare secret:
    //        npx wrangler secret put DC_WEBHOOK_SECRET
    //      (paste the HMAC signing secret from economy.democracycraft.net/me/webhooks)
    //   c. On economy.democracycraft.net/me/webhooks, add endpoint:
    //        https://<your-worker>.workers.dev/api/ads/webhook/payment
    //      Scope it to your firm account so you only receive inbound transfers.

    // Verify the HMAC-SHA256 signature DC Economy attaches to every webhook.
    // Must run against the raw request body bytes, not re-serialised JSON.
    async function verifyDcWebhookSignature(rawBody, signatureHeader, secret) {
      if (!signatureHeader || !signatureHeader.startsWith('sha256=')) return false;
      const expected = signatureHeader.slice(7); // strip 'sha256='
      const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      );
      const sig = await crypto.subtle.sign('HMAC', key, rawBody);
      const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
      // Constant-time comparison
      if (hex.length !== expected.length) return false;
      let diff = 0;
      for (let i = 0; i < hex.length; i++) diff |= hex.charCodeAt(i) ^ expected.charCodeAt(i);
      return diff === 0;
    }

    // Parse the memo field from a DC Economy transaction.
    // Advertisers must pay with memo = "bid:<id>" (e.g. "bid:42").
    // Returns the bid id as a number, or null if memo doesn't match.
    function parseBidIdFromMemo(memo) {
      if (!memo || typeof memo !== 'string') return null;
      const m = memo.trim().match(/^bid:(\d+)$/i);
      return m ? parseInt(m[1], 10) : null;
    }
    // ----------------------------------------------------------------

    // GET /api/ads/bids?date=YYYY-MM-DD&slot=1  — public
    // Returns top 3 current bids for a given date+slot so advertisers can
    // see what they need to beat. Advertiser names are shown, contacts hidden.
    if (url.pathname === '/api/ads/bids' && request.method === 'GET') {
      const date = url.searchParams.get('date');
      const slot = parseInt(url.searchParams.get('slot') || '1');
      if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date) || ![1,2,3].includes(slot)) {
        return new Response(JSON.stringify({ error: 'Invalid date or slot' }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }
      const rows = await env.DB.prepare(
        `SELECT advertiser_name, bid_amount, created_at
         FROM ad_bids
         WHERE target_date = ? AND slot_number = ? AND status = 'pending'
         ORDER BY bid_amount DESC, id ASC
         LIMIT 3`
      ).bind(date, slot).all();
      return new Response(JSON.stringify(rows.results || []), {
        headers: { 'Content-Type': 'application/json', ...securityHeaders() }
      });
    }

    // POST /api/ads/bid  — public, no auth required
    // Body: { advertiser_name, contact, image_url, dest_url, bid_amount, target_date, slot_number }
    if (url.pathname === '/api/ads/bid' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return new Response('Bad JSON', { status: 400 }); }
      const { advertiser_name, contact, email, discord_username, image_url, dest_url, bid_amount, target_date, slot_number } = body;
      if (!advertiser_name || !contact || !image_url || !dest_url || !bid_amount || !target_date || !slot_number) {
        return new Response(JSON.stringify({ error: 'Missing required fields' }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }
      if (![1, 2, 3].includes(Number(slot_number))) {
        return new Response(JSON.stringify({ error: 'slot_number must be 1, 2, or 3' }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }
      const todayStr = new Date().toISOString().slice(0, 10);
      if (target_date <= todayStr) {
        return new Response(JSON.stringify({ error: 'target_date must be a future date' }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }
      if (Number(bid_amount) <= 0) {
        return new Response(JSON.stringify({ error: 'bid_amount must be positive' }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }
      await env.DB.prepare(
        `INSERT INTO ad_bids (advertiser_name, contact, email, discord_username, image_url, dest_url, bid_amount, target_date, slot_number)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(advertiser_name, contact, email || '', discord_username || '', image_url, dest_url, Number(bid_amount), target_date, Number(slot_number)).run();
      return new Response(JSON.stringify({ ok: true, message: 'Bid received. Winners notified after 8 PM UTC.' }), {
        headers: { 'Content-Type': 'application/json', ...securityHeaders() }
      });
    }

    // GET /api/ads/current
    // Returns the 3 active ad slots for today. Article pages call this on load
    // instead of using hardcoded AD_IMAGE_URL constants.
    // Also records one impression per slot per request.
    if (url.pathname === '/api/ads/current' && request.method === 'GET') {
      const today = new Date().toISOString().slice(0, 10);
      const rows = await env.DB.prepare(
        `SELECT id, slot_number, image_url, dest_url, advertiser_name
         FROM ad_slots WHERE run_date = ? ORDER BY slot_number`
      ).bind(today).all();
      const visitorId = request.headers.get('Cookie')?.match(/jni_vid=([^;]+)/)?.[1] || null;
      for (const row of (rows.results || [])) {
        await env.DB.prepare(
          `INSERT INTO ad_events (ad_slot_id, event_type, visitor_id) VALUES (?, 'impression', ?)`
        ).bind(row.id, visitorId).run();
        await env.DB.prepare(
          `UPDATE ad_slots SET impressions = impressions + 1 WHERE id = ?`
        ).bind(row.id).run();
      }
      return new Response(JSON.stringify(rows.results || []), {
        headers: { 'Content-Type': 'application/json', ...securityHeaders() }
      });
    }

    // GET /api/ads/click/:slotId
    // Records the click then redirects to the ad's destination URL.
    if (url.pathname.startsWith('/api/ads/click/') && request.method === 'GET') {
      const slotId = parseInt(url.pathname.slice('/api/ads/click/'.length));
      if (!slotId) return new Response('Bad request', { status: 400 });
      const row = await env.DB.prepare(
        `SELECT dest_url FROM ad_slots WHERE id = ?`
      ).bind(slotId).first();
      if (!row) return new Response('Ad not found', { status: 404 });
      const visitorId = request.headers.get('Cookie')?.match(/jni_vid=([^;]+)/)?.[1] || null;
      await env.DB.prepare(
        `INSERT INTO ad_events (ad_slot_id, event_type, visitor_id) VALUES (?, 'click', ?)`
      ).bind(slotId, visitorId).run();
      await env.DB.prepare(
        `UPDATE ad_slots SET clicks = clicks + 1 WHERE id = ?`
      ).bind(slotId).run();
      return Response.redirect(row.dest_url, 302);
    }

    // POST /api/ads/report  — editor/admin only
    // Body: { token, from_date?, to_date? }
    if (url.pathname === '/api/ads/report' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return new Response('Bad JSON', { status: 400 }); }
      const { token, from_date, to_date } = body;
      const session = token ? await env.DB.prepare(
        `SELECT u.role FROM sessions s JOIN users u ON u.username = s.username
         WHERE s.token = ? AND s.expires_at > datetime('now')`
      ).bind(token).first() : null;
      if (!session || !['admin', 'editor'].includes(session.role)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
      }
      const from = from_date || new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
      const to   = to_date   || new Date().toISOString().slice(0, 10);
      const rows = await env.DB.prepare(
        `SELECT s.id, s.slot_number, s.run_date, s.advertiser_name, s.contact,
                s.bid_amount, s.impressions, s.clicks,
                CASE WHEN s.impressions > 0 THEN ROUND(100.0*s.clicks/s.impressions,2) ELSE 0 END AS ctr
         FROM ad_slots s
         WHERE s.run_date BETWEEN ? AND ?
         ORDER BY s.run_date DESC, s.slot_number`
      ).bind(from, to).all();
      return new Response(JSON.stringify(rows.results || []), {
        headers: { 'Content-Type': 'application/json', ...securityHeaders() }
      });
    }

    // ================================================================
    // POST /api/ads/webhook/payment  — DC Economy webhook receiver
    // ================================================================
    // Called by DC Economy server when money arrives in the JNI firm account.
    // Verifies the HMAC signature, deduplicates by deliveryId, parses the
    // memo to find the matching bid, and marks it paid (or flags over/underpay).
    if (url.pathname === '/api/ads/webhook/payment' && request.method === 'POST') {
      const secret = env.DC_WEBHOOK_SECRET;
      if (!secret) {
        // Secret not configured — log and return 200 so DC doesn't retry forever
        console.error('DC_WEBHOOK_SECRET not set — webhook ignored');
        return new Response('ok', { status: 200 });
      }

      // Read raw bytes for signature verification
      const rawBody = await request.arrayBuffer();
      const sigHeader = request.headers.get('X-Treasury-Signature') || '';
      const deliveryId = request.headers.get('X-Treasury-Delivery-Id') || String(Date.now());

      // Verify signature
      const valid = await verifyDcWebhookSignature(rawBody, sigHeader, secret);
      if (!valid) {
        console.warn('DC webhook: invalid signature, rejecting');
        return new Response('Forbidden', { status: 403 });
      }

      // Deduplicate: if we've already processed this deliveryId, return 200 silently
      const alreadyProcessed = await env.DB.prepare(
        `SELECT id FROM webhook_deliveries WHERE delivery_id = ?`
      ).bind(deliveryId).first();
      if (alreadyProcessed) {
        return new Response('ok', { status: 200 }); // idempotent replay
      }

      // Parse payload
      let payload;
      try { payload = JSON.parse(new TextDecoder().decode(rawBody)); }
      catch { return new Response('Bad JSON', { status: 400 }); }

      const txn = payload.transaction;
      if (!txn) return new Response('ok', { status: 200 }); // not a transaction event

      // Only care about incoming money (positive amount)
      const amount = parseFloat(txn.amount);
      if (!amount || amount <= 0) return new Response('ok', { status: 200 });

      // Record delivery for deduplication regardless of outcome
      await env.DB.prepare(
        `INSERT OR IGNORE INTO webhook_deliveries (delivery_id, txn_id) VALUES (?, ?)`
      ).bind(deliveryId, String(txn.txnId || '')).run();

      // Parse bid ID from memo
      const bidId = parseBidIdFromMemo(txn.memo || txn.message || '');
      if (!bidId) {
        // Payment with no recognisable bid ID — log but don't error (might be unrelated)
        console.log(`DC webhook: unrecognised memo "${txn.memo}" — ignoring`);
        return new Response('ok', { status: 200 });
      }

      // Look up the bid
      const bid = await env.DB.prepare(
        `SELECT * FROM ad_bids WHERE id = ?`
      ).bind(bidId).first();

      if (!bid) {
        console.warn(`DC webhook: bid ${bidId} not found`);
        return new Response('ok', { status: 200 });
      }

      // Determine payment status
      let paymentStatus;
      const tolerance = 0.01; // float rounding tolerance
      if (Math.abs(amount - bid.bid_amount) <= tolerance) {
        paymentStatus = 'paid';
      } else if (amount > bid.bid_amount) {
        paymentStatus = 'overpaid';
      } else {
        paymentStatus = 'underpaid';
      }

      // Update bid with payment details
      await env.DB.prepare(
        `UPDATE ad_bids
         SET payment_status = ?,
             payment_txn_id = ?,
             payment_amount_received = ?,
             payment_received_at = datetime('now')
         WHERE id = ?`
      ).bind(paymentStatus, String(txn.txnId || txn.postingId || deliveryId), amount, bidId).run();

      console.log(`DC webhook: bid ${bidId} marked ${paymentStatus} (expected ${bid.bid_amount}, received ${amount})`);

      // Send payment confirmation (email + Discord DM)
      if (paymentStatus === 'paid' || paymentStatus === 'overpaid') {
        const slotLabelPay = SLOT_LABELS[bid.slot_number] || `Slot ${bid.slot_number}`;
        if (bid.email) {
          await sendEmail(env, {
            to: bid.email,
            subject: `✅ Payment confirmed — Jaronite News ad #${bid.id}`,
            html: paymentConfirmedEmailHtml(bid, slotLabel, amount),
          });
        }
        if (bid.discord_username) {
          await sendDiscordDm(env, bid.discord_username, confirmedDiscordMsg(bid, slotLabelPay, amount));
        }
      }

      return new Response('ok', { status: 200 });
    }

    // ================================================================
    // GET /api/ads/payment-status  — editor/admin only
    // Returns payment status for all won bids, optionally filtered by date range.
    // Query params: token (required), from_date, to_date
    // ================================================================
    if (url.pathname === '/api/ads/payment-status' && request.method === 'GET') {
      const token = url.searchParams.get('token');

      // Auth path 1: a permanent bot API key (machine-to-machine, no expiry).
      // Set via: npx wrangler secret put BOT_API_KEY
      const botKey = env.BOT_API_KEY;
      const presentedKey = request.headers.get('X-Bot-Key') || url.searchParams.get('bot_key');
      const isBot = botKey && presentedKey &&
        presentedKey.length === botKey.length &&
        timingSafeEqualStr(presentedKey, botKey);

      // Auth path 2: a normal staff session (editor/admin).
      const session = (!isBot && token) ? await env.DB.prepare(
        `SELECT u.role FROM sessions s JOIN users u ON u.username = s.username
         WHERE s.token = ? AND s.expires_at > datetime('now')`
      ).bind(token).first() : null;

      if (!isBot && (!session || !['admin', 'editor'].includes(session.role))) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 403, headers: { 'Content-Type': 'application/json' }
        });
      }
      const from = url.searchParams.get('from_date') || new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
      const to   = url.searchParams.get('to_date')   || new Date().toISOString().slice(0, 10);
      const rows = await env.DB.prepare(
        `SELECT b.id, b.advertiser_name, b.contact, b.bid_amount,
                b.target_date, b.slot_number, b.status AS bid_status,
                b.payment_status, b.payment_amount_received,
                b.payment_txn_id, b.payment_received_at
         FROM ad_bids b
         WHERE b.status = 'won' AND b.target_date BETWEEN ? AND ?
         ORDER BY b.target_date DESC, b.slot_number`
      ).bind(from, to).all();
      return new Response(JSON.stringify(rows.results || []), {
        headers: { 'Content-Type': 'application/json', ...securityHeaders() }
      });
    }

    // /advertise → advertise.html (public bid form)
    if (url.pathname === '/advertise') {
      const advUrl = new URL('/advertise.html', url.origin);
      try {
        const advAsset = await getAssetFromKV(
          { request: new Request(advUrl.toString(), request), waitUntil(p) { return ctx.waitUntil(p); } },
          { ASSET_NAMESPACE: env.__STATIC_CONTENT, ASSET_MANIFEST: assetManifest }
        );
        const advH = new Headers(advAsset.headers);
        for (const [k, v] of Object.entries(securityHeaders())) advH.set(k, v);
        return new Response(advAsset.body, { status: advAsset.status, headers: advH });
      } catch (e) {
        return new Response('Not found', { status: 404 });
      }
    }

    // Clean-URL support: getAssetFromKV matches the exact pathname in the KV
    // manifest, so "/portal" would 404 even though "/portal.html" exists.
    // If the requested path has no file extension (and isn't the root "/"),
    // try appending ".html" first. This lets every page be reached at its
    // clean URL (/portal, /politics, /economy, ...) while old links that
    // still include ".html" keep working too, since we fall back to the
    // original request if the rewritten one doesn't resolve.
    //
    // /article/* is a special case: these are dynamic article pages with no
    // corresponding static file per article. They all share a single
    // article.html shell that reads the id-slug from the URL client-side and
    // fetches the article data from /api/article/:idslug.
    // /articles -> articles.html (All Articles page)
    if (url.pathname === "/articles") {
      const articlesUrl = new URL("/articles.html", url.origin);
      try {
        const ar = await getAssetFromKV(
          { request: new Request(articlesUrl.toString(), request), waitUntil(p) { return ctx.waitUntil(p); } },
          { ASSET_NAMESPACE: env.__STATIC_CONTENT, ASSET_MANIFEST: assetManifest }
        );
        const arH = new Headers(ar.headers); for (const [k,v] of Object.entries(securityHeaders())) arH.set(k,v);
        return new Response(ar.body, { status: ar.status, headers: arH });
      } catch (e) {
        return new Response("Not found", { status: 404 });
      }
    }

    // /favorites -> favorites.html (dedicated Favorites page for logged-in readers)
    if (url.pathname === "/favorites") {
      const favUrl = new URL("/favorites.html", url.origin);
      try {
        const fv = await getAssetFromKV(
          { request: new Request(favUrl.toString(), request), waitUntil(p) { return ctx.waitUntil(p); } },
          { ASSET_NAMESPACE: env.__STATIC_CONTENT, ASSET_MANIFEST: assetManifest }
        );
        const fvH = new Headers(fv.headers); for (const [k,v] of Object.entries(securityHeaders())) fvH.set(k,v);
        return new Response(fv.body, { status: fv.status, headers: fvH });
      } catch (e) {
        return new Response("Not found", { status: 404 });
      }
    }

    if (url.pathname.startsWith("/article/")) {
      const articleUrl = new URL("/article.html", url.origin);
      const articleRequest = new Request(articleUrl.toString(), request);
      try {
        const ar2 = await getAssetFromKV(
          { request: articleRequest, waitUntil(promise) { return ctx.waitUntil(promise); } },
          { ASSET_NAMESPACE: env.__STATIC_CONTENT, ASSET_MANIFEST: assetManifest }
        );
        const ar2H = new Headers(ar2.headers); for (const [k,v] of Object.entries(securityHeaders())) ar2H.set(k,v);
        return new Response(ar2.body, { status: ar2.status, headers: ar2H });
      } catch (e) {
        return new Response("Article page not found", { status: 404 });
      }
    }

    // Any /api/* path that didn't match a real route above gets a clean JSON 404
    // rather than falling through into the static-asset handler.
    if (url.pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...securityHeaders() }
      });
    }

    const hasExtension = /\.[a-zA-Z0-9]+$/.test(url.pathname);
    if (!hasExtension && url.pathname !== "/") {
      try {
        const htmlUrl = new URL(url.pathname.replace(/\/$/, "") + ".html", url.origin);
        const htmlRequest = new Request(htmlUrl.toString(), request);
        const htmlAsset = await getAssetFromKV(
          { request: htmlRequest, waitUntil(promise) { return ctx.waitUntil(promise); } },
          { ASSET_NAMESPACE: env.__STATIC_CONTENT, ASSET_MANIFEST: assetManifest }
        );
        const htmlH = new Headers(htmlAsset.headers); for (const [k,v] of Object.entries(securityHeaders())) htmlH.set(k,v);
        return new Response(htmlAsset.body, { status: htmlAsset.status, headers: htmlH });
      } catch (e) {
        // No matching .html file — fall through to the normal lookup below
        // (covers extensionless static assets, if any, and produces the
        // standard 404 if nothing matches either way).
      }
    }

    try {
      const assetResponse = await getAssetFromKV(
        { request, waitUntil(promise) { return ctx.waitUntil(promise); } },
        { ASSET_NAMESPACE: env.__STATIC_CONTENT, ASSET_MANIFEST: assetManifest }
      );
      // Inject security headers on every served HTML/JS/CSS asset.
      const newHeaders = new Headers(assetResponse.headers);
      for (const [k, v] of Object.entries(securityHeaders())) newHeaders.set(k, v);
      return new Response(assetResponse.body, { status: assetResponse.status, headers: newHeaders });
    } catch (e) {
      return new Response("404 Not Found", { status: 404 });
    }
  },

  // ================================================================
  // CRON — Ad system automation
  // Runs at 8 PM UTC (award bids) and midnight UTC (safety check).
  // ================================================================
  async scheduled(event, env, ctx) {
    const hour = new Date().getUTCHours();

    // ---- 8 PM UTC: award tomorrow's bids ----
    if (hour === 20) {
      const tomorrow = new Date();
      tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
      const targetDate = tomorrow.toISOString().slice(0, 10);

      // For each of the 3 slots, find the highest bid for tomorrow.
      // Ties broken by earliest submission (lowest id).
      for (let slot = 1; slot <= 3; slot++) {
        const winner = await env.DB.prepare(
          `SELECT * FROM ad_bids
           WHERE target_date = ? AND slot_number = ? AND status = 'pending'
           ORDER BY bid_amount DESC, id ASC LIMIT 1`
        ).bind(targetDate, slot).first();

        if (!winner) continue;

        // Insert into ad_slots (or update if already exists from a re-run)
        await env.DB.prepare(
          `INSERT INTO ad_slots (slot_number, run_date, bid_id, advertiser_name, contact, image_url, dest_url, bid_amount)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(slot_number, run_date) DO UPDATE SET
             bid_id = excluded.bid_id,
             advertiser_name = excluded.advertiser_name,
             contact = excluded.contact,
             image_url = excluded.image_url,
             dest_url = excluded.dest_url,
             bid_amount = excluded.bid_amount`
        ).bind(slot, targetDate, winner.id, winner.advertiser_name, winner.contact, winner.image_url, winner.dest_url, winner.bid_amount).run();

        // Mark winner and set payment_status to awaiting_payment
        await env.DB.prepare(
          `UPDATE ad_bids SET status = 'won', payment_status = 'awaiting_payment' WHERE id = ?`
        ).bind(winner.id).run();

        // Send win notifications (email + Discord DM)
        const slotLabelWin = SLOT_LABELS[slot] || `Slot ${slot}`;
        if (winner.email) {
          await sendEmail(env, {
            to: winner.email,
            subject: `🎉 You won a Jaronite News ad slot for ${targetDate}!`,
            html: winEmailHtml(winner, slotLabelWin),
          });
        }
        if (winner.discord_username) {
          await sendDiscordDm(env, winner.discord_username, winDiscordMsg(winner, slotLabelWin));
        }

        // Mark all other pending bids for this slot/date as lost
        await env.DB.prepare(
          `UPDATE ad_bids SET status = 'lost'
           WHERE target_date = ? AND slot_number = ? AND status = 'pending' AND id != ?`
        ).bind(targetDate, slot, winner.id).run();
      }
    }

    // ---- Midnight UTC: clean up pending bids + send payment reminders ----
    if (hour === 0) {
      const today = new Date().toISOString().slice(0, 10);
      await env.DB.prepare(
        `UPDATE ad_bids SET status = 'lost'
         WHERE target_date <= ? AND status = 'pending'`
      ).bind(today).run();

      // Send reminder emails for won-but-unpaid bids where the ad date is still upcoming
      const unpaid = await env.DB.prepare(
        `SELECT * FROM ad_bids
         WHERE status = 'won'
           AND payment_status IN ('awaiting_payment', 'underpaid')
           AND target_date > ?
           AND email IS NOT NULL AND email != ''`
      ).bind(today).all();

      for (const bid of (unpaid.results || [])) {
        const wonAt = new Date(bid.updated_at || bid.created_at);
        const daysOverdue = Math.floor((Date.now() - wonAt.getTime()) / 86400000);
        const slotLabel = SLOT_LABELS[bid.slot_number] || `Slot ${bid.slot_number}`;
        if (bid.email) {
          await sendEmail(env, {
            to: bid.email,
            subject: `⏰ Reminder: payment pending for your Jaronite News ad #${bid.id}`,
            html: reminderEmailHtml(bid, slotLabel, daysOverdue),
          });
        }
        if (bid.discord_username) {
          await sendDiscordDm(env, bid.discord_username, reminderDiscordMsg(bid, slotLabel));
        }
      }
    }
  },
};