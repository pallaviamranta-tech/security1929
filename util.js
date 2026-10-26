/** Small pure helpers shared by the bot modules. */

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export function isGroup(ctx) {
  return ["group", "supergroup"].includes(ctx.chat?.type);
}

export function privateOnly(ctx) {
  return ctx.chat?.type === "private";
}

export function displayName(user) {
  return [user?.first_name, user?.last_name].filter(Boolean).join(" ")
    || user?.username
    || String(user?.id || "Unknown");
}

/** Escape text for Telegram HTML parse mode. */
export function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function mention(user) {
  return `<a href="tg://user?id=${user.id}">${esc(displayName(user))}</a>`;
}

/** Text after the command, e.g. "10m spam" for "/mute@bot 10m spam". */
export function commandArgs(ctx) {
  return (ctx.message?.text || "")
    .replace(/^\/\w+(?:@\w+)?\s*/i, "")
    .trim();
}

export function parseDuration(s) {
  const m = /^(\d+)(s|m|h|d)$/i.exec(String(s || ""));
  if (!m) return null;

  const n = Number(m[1]);
  if (!Number.isSafeInteger(n) || n < 1) return null;

  const unit = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2].toLowerCase()];
  const ms = n * unit;

  return ms <= 366 * 86400000 ? ms : null;
}

export function formatRemaining(ms) {
  const total = Math.max(1, Math.ceil(ms / 1000));
  const d = Math.floor(total / 86400);
  const h = Math.floor((total % 86400) / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;

  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

export function userIdFromText(s) {
  const n = String(s || "").trim();
  return /^\d{5,20}$/.test(n) ? n : null;
}

export function repliedUser(ctx) {
  const u = ctx.message?.reply_to_message?.from;
  return u && !u.is_bot ? u : null;
}

export function errorText(e) {
  return e?.description || e?.message || "Unknown error";
}

export function withReason(reason) {
  return reason ? `\nReason: ${esc(reason)}` : "";
}

const LINK_PATTERN = /(?:https?:\/\/|www\.|t\.me\/|telegram\.me\/|telegram\.dog\/|tg:\/\/)/i;

/** True if a message contains a link (plain text, caption, or hidden text link). */
export function hasLink(m) {
  const text = `${m.text || ""}\n${m.caption || ""}`;
  if (LINK_PATTERN.test(text)) return true;

  const entities = [...(m.entities || []), ...(m.caption_entities || [])];
  return entities.some(e => ["url", "text_link"].includes(e.type));
}

export function isCommandMessage(m) {
  return typeof m?.text === "string" && /^\/[a-z0-9_]+(?:@\w+)?(?:\s|$)/i.test(m.text);
}
