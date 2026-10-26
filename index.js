/**
 * 18n28 Security Bot - Cloudflare Worker entry point (Telegram webhook).
 *
 * Telegram sends every update as an HTTPS POST to /webhook with the header
 * "X-Telegram-Bot-Api-Secret-Token". Requests without the correct secret are rejected.
 */
import { createBot } from "./bot.js";
import { errorText } from "./util.js";

const MAX_BODY_BYTES = 1_000_000;
let botInfoCache = null; // Bot identity, cached per Worker isolate to save one API call per update.

/** Constant-time string comparison (compares SHA-256 digests of both values). */
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b))
  ]);

  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(ha, hb);
  }

  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/** Returns a description of a configuration problem, or null when everything is set. */
function configProblem(env) {
  if (!env.DB) return "D1 binding DB is missing";
  if (!env.BOT_TOKEN) return "BOT_TOKEN secret is missing";
  if (!env.WEBHOOK_SECRET) return "WEBHOOK_SECRET secret is missing";
  if (!/^\d+$/.test(String(env.MAIN_OWNER_ID || ""))) return "MAIN_OWNER_ID secret is missing or not numeric";
  return null;
}

async function getBotInfo(env) {
  if (botInfoCache) return botInfoCache;

  const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/getMe`);
  const data = await res.json();
  if (!data.ok) throw new Error(`getMe failed: ${data.description || res.status}`);

  botInfoCache = data.result;
  return botInfoCache;
}

async function processUpdate(update, env, ctx) {
  try {
    const botInfo = await getBotInfo(env);
    const bot = createBot(env, botInfo, ctx);
    await bot.handleUpdate(update);
  } catch (err) {
    console.error(`Update ${update?.update_id ?? "unknown"} failed:`, errorText(err));
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Simple health check (reveals nothing sensitive).
    if (url.pathname === "/" || url.pathname === "/health") {
      return new Response("18n28 Security Bot is running.", { status: 200 });
    }

    if (url.pathname !== "/webhook") {
      return new Response("Not found", { status: 404 });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405, headers: { Allow: "POST" } });
    }

    const problem = configProblem(env);
    if (problem) {
      console.error(`Configuration error: ${problem}`);
      return new Response("Server configuration error", { status: 500 });
    }

    // 1) Verify the secret token that Telegram attaches to every webhook request.
    const provided = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
    if (!(await safeEqual(provided, env.WEBHOOK_SECRET))) {
      return new Response("Forbidden", { status: 403 });
    }

    // 2) Validate the request body.
    if (!(request.headers.get("Content-Type") || "").toLowerCase().includes("application/json")) {
      return new Response("Unsupported media type", { status: 415 });
    }
    if (Number(request.headers.get("Content-Length") || 0) > MAX_BODY_BYTES) {
      return new Response("Payload too large", { status: 413 });
    }

    let update;
    try {
      update = await request.json();
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    if (!update || typeof update !== "object" || !Number.isSafeInteger(update.update_id)) {
      return new Response("Bad request", { status: 400 });
    }

    // 3) Acknowledge immediately (Telegram will not retry) and process in the background.
    ctx.waitUntil(processUpdate(update, env, ctx));
    return new Response("OK", { status: 200 });
  }
};
