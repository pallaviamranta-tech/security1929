/**
 * Helper for managing the Telegram webhook from Windows (or any OS) without typing long curl commands.
 *
 * Usage (run from the project folder):
 *   npm run webhook:set -- https://security-bot-18n28.YOUR-SUBDOMAIN.workers.dev
 *   npm run webhook:info
 *   npm run webhook:delete
 *
 * It reads BOT_TOKEN and WEBHOOK_SECRET from the file ".dev.vars" (or from environment variables).
 */
import { readFileSync, existsSync } from "node:fs";

const ALLOWED_UPDATES = ["message", "chat_member", "my_chat_member", "callback_query"];

function loadVars() {
  const vars = {};
  if (existsSync(".dev.vars")) {
    for (const line of readFileSync(".dev.vars", "utf8").split(/\r?\n/)) {
      const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
      if (!m || line.trim().startsWith("#")) continue;
      vars[m[1]] = m[2].replace(/^(['"])(.*)\1$/, "$2");
    }
  }
  return {
    BOT_TOKEN: process.env.BOT_TOKEN || vars.BOT_TOKEN,
    WEBHOOK_SECRET: process.env.WEBHOOK_SECRET || vars.WEBHOOK_SECRET
  };
}

async function callTelegram(token, method, body) {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
  return res.json();
}

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exit(1);
}

const [command, urlArg] = process.argv.slice(2);
const { BOT_TOKEN, WEBHOOK_SECRET } = loadVars();

if (!BOT_TOKEN || BOT_TOKEN.startsWith("PASTE_")) fail("BOT_TOKEN is missing. Fill it in the .dev.vars file.");

if (command === "set") {
  if (!WEBHOOK_SECRET || WEBHOOK_SECRET.startsWith("PASTE_")) fail("WEBHOOK_SECRET is missing in .dev.vars.");
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(WEBHOOK_SECRET)) {
    fail("WEBHOOK_SECRET may only contain letters, digits, underscore and hyphen (1-256 characters).");
  }
  if (!urlArg || !/^https:\/\//i.test(urlArg)) fail("Give your Worker URL, e.g. https://security-bot-18n28.example.workers.dev");

  const webhookUrl = urlArg.replace(/\/+$/, "").replace(/\/webhook$/, "") + "/webhook";
  const result = await callTelegram(BOT_TOKEN, "setWebhook", {
    url: webhookUrl,
    secret_token: WEBHOOK_SECRET,
    allowed_updates: ALLOWED_UPDATES,
    max_connections: 40,
    drop_pending_updates: true
  });

  console.log(result.ok ? `Webhook set to ${webhookUrl}` : `Telegram error: ${result.description}`);
  process.exit(result.ok ? 0 : 1);
} else if (command === "info") {
  const result = await callTelegram(BOT_TOKEN, "getWebhookInfo");
  if (!result.ok) fail(result.description);

  const i = result.result;
  console.log(`Webhook URL        : ${i.url || "(none)"}`);
  console.log(`Pending updates    : ${i.pending_update_count}`);
  console.log(`Allowed updates    : ${(i.allowed_updates || ["(default)"]).join(", ")}`);
  console.log(`Last error message : ${i.last_error_message || "(none)"}`);
  console.log(`Last error date    : ${i.last_error_date ? new Date(i.last_error_date * 1000).toISOString() : "(none)"}`);
} else if (command === "delete") {
  const result = await callTelegram(BOT_TOKEN, "deleteWebhook", { drop_pending_updates: false });
  console.log(result.ok ? "Webhook deleted." : `Telegram error: ${result.description}`);
  process.exit(result.ok ? 0 : 1);
} else {
  fail("Unknown command. Use: set <worker-url> | info | delete");
}
