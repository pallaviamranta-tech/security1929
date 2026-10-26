/**
 * Static configuration for 18n28 Security Bot.
 * Secrets (bot token, webhook secret, main owner ID) are NOT stored here.
 * They are provided as Cloudflare Worker secrets (see wrangler.jsonc).
 */

export const SUPPORT_TEXT = "https://t.me/+ViokM7A2VEs5MGU1";
export const DEFAULT_RULES = "Be respectful. Do not spam, scam, or post unwanted links.";

export const MAX_HISTORY = 300;          // join history entries kept per group
export const MAX_AUDIT_LOGS = 500;       // audit log entries kept in total
export const MAX_REPORTS = 500;          // reports kept in total
export const MAX_WARNINGS_BEFORE_BAN = 3;

export const ADMIN_CACHE_TTL_MS = 30 * 1000;
export const FLOOD_WINDOW_MS = 5 * 1000;
export const FLOOD_MAX_MESSAGES = 6;
export const FLOOD_MUTE_SECONDS = 60;
export const REPORT_COOLDOWN_MS = 30 * 1000;
export const NOTICE_COOLDOWN_MS = 15 * 1000;
export const PENDING_ACTION_TTL_MS = 5 * 60 * 1000;
export const JOIN_DEDUPE_MS = 10 * 1000;

// Telegram 429 handling: wait at most this long before one retry.
export const MAX_RETRY_WAIT_SECONDS = 5;
// Free plan allows 50 external subrequests per invocation, so cap owner notifications.
export const MAX_REPORT_RECIPIENTS = 20;

export const ALLOWED_UPDATES = ["message", "chat_member", "my_chat_member", "callback_query"];

export const DEFAULT_SETTINGS = { welcome: true, antilink: false, antiflood: false };

// Timed protection commands -> protection type stored in D1.
export const TIMED_COMMANDS = {
  stopsticker: "sticker",
  stoppdf: "document",
  stopvideo: "video",
  stoplink: "link",
  stopmedia: "media",
  stopall: "all"
};

export const NO_SEND_PERMISSIONS = {
  can_send_messages: false,
  can_send_audios: false,
  can_send_documents: false,
  can_send_photos: false,
  can_send_videos: false,
  can_send_video_notes: false,
  can_send_voice_notes: false,
  can_send_polls: false,
  can_send_other_messages: false,
  can_add_web_page_previews: false
};

export const FULL_PERMISSIONS = {
  can_send_messages: true,
  can_send_audios: true,
  can_send_documents: true,
  can_send_photos: true,
  can_send_videos: true,
  can_send_video_notes: true,
  can_send_voice_notes: true,
  can_send_polls: true,
  can_send_other_messages: true,
  can_add_web_page_previews: true
};
