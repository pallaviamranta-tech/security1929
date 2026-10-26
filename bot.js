/**
 * 18n28 Security Bot - bot logic (grammY, Cloudflare Workers webhook mode).
 * A new Bot instance is created for every incoming update, so all durable state
 * lives in D1. Small in-memory caches below are best-effort per Worker isolate.
 */
import { Bot, InlineKeyboard } from "grammy";
import {
  SUPPORT_TEXT, MAX_WARNINGS_BEFORE_BAN, ADMIN_CACHE_TTL_MS, FLOOD_WINDOW_MS, FLOOD_MAX_MESSAGES,
  FLOOD_MUTE_SECONDS, REPORT_COOLDOWN_MS, NOTICE_COOLDOWN_MS, PENDING_ACTION_TTL_MS,
  MAX_RETRY_WAIT_SECONDS, MAX_REPORT_RECIPIENTS, TIMED_COMMANDS, NO_SEND_PERMISSIONS, FULL_PERMISSIONS
} from "./config.js";
import {
  sleep, isGroup, privateOnly, displayName, esc, mention, commandArgs, parseDuration, formatRemaining,
  userIdFromText, repliedUser, errorText, withReason, hasLink, isCommandMessage
} from "./util.js";
import * as D from "./db.js";

// ---------- best-effort per-isolate caches (not shared between isolates) ----------
const adminCache = new Map();
const floodTracker = new Map();
const reportCooldowns = new Map();
const noticeCooldowns = new Map();
let profilePhotoId = null;
let profilePhotoChecked = false;

function pruneCaches() {
  const now = Date.now();
  if (adminCache.size > 500) for (const [k, v] of adminCache) if (v.expires < now) adminCache.delete(k);
  if (floodTracker.size > 500) {
    for (const [k, times] of floodTracker) {
      if (!times.length || now - times[times.length - 1] > FLOOD_WINDOW_MS) floodTracker.delete(k);
    }
  }
  if (reportCooldowns.size > 500) for (const [k, t] of reportCooldowns) if (now - t > REPORT_COOLDOWN_MS) reportCooldowns.delete(k);
  if (noticeCooldowns.size > 500) for (const [k, t] of noticeCooldowns) if (now - t > NOTICE_COOLDOWN_MS) noticeCooldowns.delete(k);
}

const HTML = { parse_mode: "HTML", link_preview_options: { is_disabled: true } };

/**
 * @param {{ BOT_TOKEN: string, MAIN_OWNER_ID: string, DB: D1Database }} env
 * @param {object} botInfo result of Telegram getMe
 * @param {{ waitUntil(p: Promise<unknown>): void }} exec Worker execution context
 */
export function createBot(env, botInfo, exec) {
  pruneCaches();

  const bot = new Bot(env.BOT_TOKEN, { botInfo });
  const db = env.DB;
  const mainOwnerId = String(env.MAIN_OWNER_ID);

  // Per-update caches (one Bot instance handles exactly one update).
  let globalOwnersCache = null;
  const groupCache = new Map();

  // ---------- Telegram rate limits: retry once on HTTP 429 ----------
  bot.api.config.use(async (prev, method, payload, signal) => {
    let result = await prev(method, payload, signal);
    const wait = Number(result.parameters?.retry_after || 0);

    if (!result.ok && result.error_code === 429 && wait > 0 && wait <= MAX_RETRY_WAIT_SECONDS) {
      await sleep(wait * 1000 + 250);
      result = await prev(method, payload, signal);
    }
    return result;
  });

  // ======================== HELPERS ========================
  const replyHtml = (ctx, html) => ctx.reply(html, HTML);

  async function notify(ctx, html, ttlMs = 8000) {
    try {
      const sent = await ctx.api.raw.sendMessage({ chat_id: ctx.chat.id, text: html, ...HTML });
      exec.waitUntil((async () => {
        await sleep(ttlMs);
        try {
          await ctx.api.raw.deleteMessage({ chat_id: ctx.chat.id, message_id: sent.message_id });
        } catch {
          // Message may already be gone.
        }
      })());
    } catch {
      // Ignore notification failures.
    }
  }

  async function logAction(ctx, action, targetId = null, extra = {}) {
    try {
      await D.logAction(db, {
        chatId: ctx.chat?.id ?? null, actorId: ctx.from?.id ?? null, targetId, action, extra
      });
    } catch (e) {
      console.warn("Audit log failed:", errorText(e));
    }
  }

  const isMainOwner = id => String(id) === mainOwnerId;

  async function globalOwnerSet() {
    if (!globalOwnersCache) globalOwnersCache = await D.listGlobalOwners(db);
    return globalOwnersCache;
  }

  async function isGlobalOwner(id) {
    return isMainOwner(id) || (await globalOwnerSet()).has(String(id));
  }

  async function groupFor(chat) {
    const key = String(chat.id);
    if (!groupCache.has(key)) {
      const state = await D.loadGroup(db, chat);
      groupCache.set(key, state);
      if (!globalOwnersCache) globalOwnersCache = state.globalOwners;
    }
    return groupCache.get(key);
  }

  const group = ctx => groupFor(ctx.chat);

  const isAnonymousAdmin = ctx =>
    Boolean(ctx.message?.sender_chat && ctx.message.sender_chat.id === ctx.chat?.id);

  async function getAdminStatus(ctx, userId = ctx.from?.id) {
    if (!isGroup(ctx) || !userId) return false;
    if (userId === ctx.from?.id && isAnonymousAdmin(ctx)) return true;

    const g = await group(ctx);
    if ((await isGlobalOwner(userId)) || g.delegatedOwners.has(String(userId))) return true;

    try {
      const m = await ctx.api.raw.getChatMember({ chat_id: ctx.chat.id, user_id: userId });
      return ["creator", "administrator"].includes(m.status);
    } catch {
      return false;
    }
  }

  async function adminOnly(ctx) {
    if (!isGroup(ctx)) {
      await ctx.reply("This command can only be used in a group.");
      return false;
    }
    if (!(await getAdminStatus(ctx))) {
      await ctx.reply("Only group administrators or authorized bot owners can use this command.");
      return false;
    }
    return true;
  }

  // Short-lived cache used by automatic protection (per isolate, best effort).
  async function getCachedStatus(ctx, userId) {
    const key = `${ctx.chat.id}:${userId}`;
    const hit = adminCache.get(key);
    if (hit && hit.expires > Date.now()) return hit.status;

    const m = await ctx.api.raw.getChatMember({ chat_id: ctx.chat.id, user_id: userId });
    adminCache.set(key, { status: m.status, expires: Date.now() + ADMIN_CACHE_TTL_MS });
    return m.status;
  }

  async function isExempt(ctx, g) {
    const uid = ctx.from.id;
    if ((await isGlobalOwner(uid)) || g.delegatedOwners.has(String(uid))) return true;

    try {
      return ["creator", "administrator"].includes(await getCachedStatus(ctx, uid));
    } catch {
      return true; // Fail open: never punish members when permissions cannot be verified.
    }
  }

  async function canModerateTarget(ctx, target) {
    if (!target) return false;

    if (String(target.id) === String(ctx.from.id)) {
      await ctx.reply("You cannot moderate yourself.");
      return false;
    }
    if (isMainOwner(target.id)) {
      await ctx.reply("The main owner cannot be moderated by this bot.");
      return false;
    }
    if ((await isGlobalOwner(target.id)) && !isMainOwner(ctx.from.id)) {
      await ctx.reply("Only the main owner can moderate a global owner.");
      return false;
    }

    try {
      const actor = isAnonymousAdmin(ctx)
        ? { status: "administrator" }
        : await ctx.api.raw.getChatMember({ chat_id: ctx.chat.id, user_id: ctx.from.id });
      const targetMember = await ctx.api.raw.getChatMember({ chat_id: ctx.chat.id, user_id: target.id });

      if (targetMember.status === "creator") {
        await ctx.reply("The group creator cannot be moderated by the bot.");
        return false;
      }
      if (
        ["creator", "administrator"].includes(targetMember.status) &&
        actor.status !== "creator" &&
        !(await isGlobalOwner(ctx.from.id))
      ) {
        await ctx.reply("You cannot moderate another administrator.");
        return false;
      }
      return true;
    } catch {
      await ctx.reply("Unable to verify the member's permissions. No action was taken.");
      return false;
    }
  }

  // Restore the group's own default permissions instead of granting everything.
  async function groupDefaultPermissions(ctx) {
    try {
      const chat = await ctx.api.raw.getChat({ chat_id: ctx.chat.id });
      if (chat.permissions) return chat.permissions;
    } catch {
      // Fall back to full permissions below.
    }
    return FULL_PERMISSIONS;
  }

  // ======================== PRIVATE DASHBOARD UI ========================
  function dashboardKeyboard() {
    return new InlineKeyboard()
      .text("Owner Setup", "dash:setup").text("Your Groups", "dash:groups").row()
      .text("Add Owner", "dash:addowner").text("Commands", "dash:commands").row()
      .text("Support", "dash:support").row()
      .url(
        "➕ Add to Group",
        botInfo.username ? `https://t.me/${botInfo.username}?startgroup=true` : "https://t.me/"
      );
  }

  async function sendDashboard(ctx) {
    const caption =
      `<b>18n28 SECURITY BOT</b>\n\nWelcome, ${esc(displayName(ctx.from))}.\n` +
      "Manage your groups and security settings from this dashboard.\n\n" +
      "Choose an option below.";

    if (!profilePhotoChecked) {
      profilePhotoChecked = true;
      try {
        const photos = await ctx.api.raw.getUserProfilePhotos({ user_id: botInfo.id, offset: 0, limit: 1 });
        if (photos.total_count > 0 && photos.photos?.[0]?.length) {
          profilePhotoId = photos.photos[0][photos.photos[0].length - 1].file_id;
        }
      } catch (e) {
        console.warn("Could not fetch bot profile photo; using text dashboard:", errorText(e));
      }
    }

    try {
      if (profilePhotoId) {
        await ctx.replyWithPhoto(profilePhotoId, {
          caption, parse_mode: "HTML", reply_markup: dashboardKeyboard()
        });
        return;
      }
    } catch {
      console.warn("Profile photo could not be sent; using text dashboard.");
    }

    await ctx.reply(caption, { parse_mode: "HTML", reply_markup: dashboardKeyboard() });
  }

  async function answerCallback(ctx) {
    try {
      await ctx.answerCallbackQuery();
    } catch {
      // Ignore expired callback queries.
    }
  }

  // ======================== JOIN TRACKING ========================
  async function recordJoin(ctx, chat, user, actorId = null) {
    if (!user || user.is_bot) return;

    const g = await groupFor(chat);
    const inserted = await D.recordJoin(db, chat.id, user, actorId);
    if (!inserted) return;

    if (g.settings.welcome) {
      try {
        await ctx.api.raw.sendMessage({
          chat_id: chat.id,
          text:
            `👋 <b>Welcome, ${esc(displayName(user))}!</b>\n\n` +
            `Welcome to <b>${esc(g.title)}</b>.\n` +
            "Please read the group rules and respect all members.\nUse /rules to view the rules.",
          parse_mode: "HTML"
        });
      } catch (e) {
        console.warn("Welcome message failed:", errorText(e));
      }
    }
  }

  bot.on("chat_member", async (ctx, next) => {
    try {
      const u = ctx.update.chat_member;
      const oldS = u.old_chat_member.status;
      const newS = u.new_chat_member.status;

      const joined =
        ["left", "kicked"].includes(oldS) &&
        ["member", "administrator", "creator", "restricted"].includes(newS);

      if (joined) await recordJoin(ctx, u.chat, u.new_chat_member.user, u.from?.id ?? null);
    } catch (e) {
      console.error("Join history update error:", errorText(e));
    }
    return next();
  });

  bot.on("my_chat_member", async ctx => {
    try {
      const u = ctx.update.my_chat_member;
      if (!["group", "supergroup"].includes(u.chat.type)) return;

      await groupFor(u.chat);

      const added =
        ["member", "administrator"].includes(u.new_chat_member.status) &&
        ["left", "kicked"].includes(u.old_chat_member.status);

      if (added) {
        await D.setGroupAddedBy(db, u.chat.id, u.from?.id ?? null);
        await logAction(ctx, "bot_added_to_group");
      }
    } catch (e) {
      console.error("Bot membership update error:", errorText(e));
    }
  });

  bot.on("message", async (ctx, next) => {
    const newMembers = ctx.message?.new_chat_members;

    if (isGroup(ctx) && Array.isArray(newMembers) && newMembers.length) {
      for (const user of newMembers) {
        await recordJoin(ctx, ctx.chat, user, ctx.from?.id ?? null);
      }
    }
    return next();
  });

  // ======================== AUTOMATIC PROTECTION ========================
  bot.on("message", async (ctx, next) => {
    if (!isGroup(ctx) || !ctx.from || ctx.from.is_bot) return next();

    // Commands are exempt from automatic deletion and flood protection.
    if (isCommandMessage(ctx.message)) return next();

    const g = await group(ctx);
    const m = ctx.message;
    const now = Date.now();
    const active = type => (g.protection[type]?.until || 0) > now;

    // Fast path: nothing to enforce, so no extra Telegram API calls are needed.
    const anyTimer = Object.values(g.protection).some(p => p.until > now);
    if (!anyTimer && !g.settings.antilink && !g.settings.antiflood) return next();

    // Decide whether this message violates a rule BEFORE checking admin status.
    let action = null;

    const blockedByTimer =
      active("all") ||
      (active("sticker") && Boolean(m.sticker)) ||
      (active("document") && Boolean(m.document)) ||
      (active("video") && Boolean(m.video || m.video_note || m.animation)) ||
      (active("link") && hasLink(m)) ||
      (
        active("media") &&
        Boolean(m.photo || m.video || m.animation || m.video_note || m.audio || m.voice || m.document)
      );

    const floodKey = `${ctx.chat.id}:${ctx.from.id}`;

    if (blockedByTimer) {
      action = "block";
    } else if (g.settings.antilink && hasLink(m)) {
      action = "link";
    } else if (g.settings.antiflood) {
      const recent = (floodTracker.get(floodKey) || []).filter(t => now - t < FLOOD_WINDOW_MS);
      recent.push(now);
      floodTracker.set(floodKey, recent);
      if (recent.length > FLOOD_MAX_MESSAGES) action = "flood";
    }

    if (!action) return next();

    if (await isExempt(ctx, g)) {
      floodTracker.delete(floodKey);
      return next();
    }

    if (action === "block") {
      try {
        await ctx.api.raw.deleteMessage({ chat_id: ctx.chat.id, message_id: m.message_id });
      } catch (e) {
        console.warn("Could not delete protected message:", errorText(e));
      }
      return;
    }

    if (action === "link") {
      try {
        await ctx.api.raw.deleteMessage({ chat_id: ctx.chat.id, message_id: m.message_id });
      } catch (e) {
        console.warn("Could not delete link message:", errorText(e));
      }

      const noticeKey = `link:${ctx.chat.id}:${ctx.from.id}`;
      if (now - (noticeCooldowns.get(noticeKey) || 0) >= NOTICE_COOLDOWN_MS) {
        noticeCooldowns.set(noticeKey, now);
        await notify(ctx, `${mention(ctx.from)}, links are not allowed in this group.`);
      }
      return;
    }

    // action === "flood"
    floodTracker.delete(floodKey);
    try {
      await ctx.api.raw.deleteMessage({ chat_id: ctx.chat.id, message_id: m.message_id });
      await ctx.api.raw.restrictChatMember({
        chat_id: ctx.chat.id,
        user_id: ctx.from.id,
        permissions: NO_SEND_PERMISSIONS,
        use_independent_chat_permissions: true,
        until_date: Math.floor(now / 1000) + FLOOD_MUTE_SECONDS
      });
      await replyHtml(ctx, `${mention(ctx.from)} was muted for ${FLOOD_MUTE_SECONDS} seconds for flooding.`);
      await logAction(ctx, "antiflood_mute", ctx.from.id);
    } catch (e) {
      console.warn("Anti-flood action failed:", errorText(e));
    }
  });

  // ======================== GENERAL COMMANDS ========================
  bot.command("start", async ctx => {
    if (privateOnly(ctx)) return sendDashboard(ctx);

    const g = await group(ctx);
    await ctx.reply(`Hello! I am 18n28 Security Bot for ${g.title}.\nUse /help to view commands.`);
  });

  bot.command("help", async ctx => {
    await ctx.reply(
`18n28 SECURITY BOT — COMMANDS

GENERAL
/start — Open the private dashboard
/help — Show this command list
/status — Show protection status
/id — Show your user ID and chat ID

GROUP SETTINGS (admins/authorized owners)
/welcome on|off — Toggle join welcome messages
/antilink on|off — Toggle anti-link protection
/antiflood on|off — Toggle anti-flood protection
/setrules Your rules — Set group rules
/rules — View group rules

MODERATION (reply to a member)
/ban [reason] — Ban a member
/unban USER_ID — Unban by numeric user ID (or reply to the user)
/kick [reason] — Remove a member (they can rejoin)
/mute 10m [reason] — Mute a member for a duration
/unmute — Unmute a member
/warn [reason] — Issue a warning; ${MAX_WARNINGS_BEFORE_BAN} warnings trigger a ban
/resetwarn — Clear a member's warnings
/pin — Pin the replied-to message
/unpin — Unpin a replied-to or the latest pinned message
/purge [1-100] — Delete the last N messages, or reply to a message to delete everything from it onward
/report — Report a replied-to message
/joinhistory — Show the 15 latest recorded joins

TIMED PROTECTION (admins/authorized owners)
/stopsticker 10m — Block stickers temporarily
/stoppdf 1h — Block documents temporarily
/stopvideo 30m — Block videos temporarily
/stoplink 10m — Block links temporarily
/stopmedia 1h — Block photos, videos, audio and documents temporarily
/stopall 1h — Block all messages from ordinary members temporarily

Duration format: 30s, 10m, 2h, 1d. The bot must be an administrator with the relevant permissions for moderation actions.`,
      { link_preview_options: { is_disabled: true } }
    );
  });

  bot.command("id", ctx =>
    ctx.reply(`Your user ID: ${ctx.from.id}\nChat ID: ${ctx.chat.id}`)
  );

  bot.command("status", async ctx => {
    if (!isGroup(ctx)) {
      return ctx.reply("The bot is running. Use /status in a group to see its settings.");
    }

    const g = await group(ctx);
    const now = Date.now();

    const active = Object.entries(g.protection)
      .filter(([, p]) => p.until > now)
      .map(([type, p]) => `${type} (${formatRemaining(p.until - now)} left)`);

    return ctx.reply(
      `18n28 SECURITY STATUS\n\nGroup: ${g.title}` +
      `\nWelcome: ${g.settings.welcome ? "ON" : "OFF"}` +
      `\nAnti-link: ${g.settings.antilink ? "ON" : "OFF"}` +
      `\nAnti-flood: ${g.settings.antiflood ? "ON" : "OFF"}` +
      `\nTimed protection: ${active.join(", ") || "None"}`
    );
  });

  // ======================== PRIVATE DASHBOARD ACTIONS ========================
  bot.callbackQuery("dash:setup", async ctx => {
    await answerCallback(ctx);

    if (!privateOnly(ctx)) {
      return ctx.reply("Open the bot in a private chat to use Owner Setup.");
    }
    if (!(await isGlobalOwner(ctx.from.id))) {
      return ctx.reply("Owner Setup is available to bot owners only.");
    }

    const owners = [...(await globalOwnerSet())];

    await ctx.reply(
      `OWNER SETUP\n\nMain owner ID: ${mainOwnerId}` +
      `\nAdditional global owners: ${owners.length ? owners.join(", ") : "None"}` +
      "\n\nThe main owner is stored in the MAIN_OWNER_ID Worker secret. To change it, run: npx wrangler secret put MAIN_OWNER_ID. Only the main owner can add global owners."
    );
  });

  bot.callbackQuery("dash:groups", async ctx => {
    await answerCallback(ctx);
    if (!privateOnly(ctx)) return;

    const groups = await D.groupsForOwner(db, ctx.from.id, await isGlobalOwner(ctx.from.id));

    if (!groups.length) {
      return ctx.reply(
        "No saved groups are associated with your account yet. Add the bot to a group and send a command there."
      );
    }

    const kb = new InlineKeyboard();
    for (const g of groups) kb.text(`⚙ ${String(g.title || g.id).slice(0, 45)}`, `group:${g.id}`).row();

    await ctx.reply("YOUR GROUPS\nSelect a group to view its saved settings.", { reply_markup: kb });
  });

  bot.callbackQuery(/^group:(-?\d+)$/, async ctx => {
    await answerCallback(ctx);
    if (!privateOnly(ctx)) return;

    const g = await D.getGroupById(db, Number(ctx.match[1]));
    if (!g) return ctx.reply("That group is not in the saved database.");

    const allowed =
      (await isGlobalOwner(ctx.from.id)) ||
      g.delegatedOwners.has(String(ctx.from.id)) ||
      String(g.addedBy || "") === String(ctx.from.id);

    if (!allowed) {
      return ctx.reply("You are not authorized to view this group's dashboard.");
    }

    await ctx.reply(
      `GROUP: ${g.title}\nID: ${g.id}` +
      `\nWelcome: ${g.settings.welcome ? "ON" : "OFF"}` +
      `\nAnti-link: ${g.settings.antilink ? "ON" : "OFF"}` +
      `\nAnti-flood: ${g.settings.antiflood ? "ON" : "OFF"}` +
      `\nRules: ${g.rules}` +
      "\n\nChange settings with /welcome, /antilink, /antiflood and /setrules inside the group."
    );
  });

  bot.callbackQuery("dash:addowner", async ctx => {
    await answerCallback(ctx);
    if (!privateOnly(ctx)) return;

    if (!isMainOwner(ctx.from.id)) {
      return ctx.reply("Only the configured main owner can add global owners.");
    }

    await D.setPending(db, ctx.from.id, "add_global_owner", Date.now() + PENDING_ACTION_TTL_MS);

    await ctx.reply(
      "Send the numeric Telegram user ID of the new global owner within 5 minutes. Send /cancel to cancel."
    );
  });

  bot.callbackQuery("dash:commands", async ctx => {
    await answerCallback(ctx);
    await ctx.reply(
      "Use /help for the complete command list, including moderation, group settings, and timed protections."
    );
  });

  bot.callbackQuery("dash:support", async ctx => {
    await answerCallback(ctx);

    await ctx.reply(
      "🛠️ SUPPORT CHANNEL\n\nJoin our support channel for help and updates.\nFor bot errors, contact the owner. Never share your bot token.",
      { reply_markup: new InlineKeyboard().url("📢 Join Support Channel", SUPPORT_TEXT) }
    );
  });

  bot.command("cancel", async ctx => {
    if (!privateOnly(ctx)) return;

    await D.clearPending(db, ctx.from.id);
    await ctx.reply("Pending action cancelled.");
  });

  bot.on("message:text", async (ctx, next) => {
    if (!privateOnly(ctx) || ctx.message.text.startsWith("/")) return next();

    const pending = await D.getPending(db, ctx.from.id);
    if (!pending) return next();

    if (Number(pending.expires_at) < Date.now()) {
      await D.clearPending(db, ctx.from.id);
      return ctx.reply("This action expired. Start again from the dashboard.");
    }

    if (pending.type === "add_global_owner") {
      if (!isMainOwner(ctx.from.id)) {
        await D.clearPending(db, ctx.from.id);
        return ctx.reply("Only the configured main owner can add global owners.");
      }

      const id = userIdFromText(ctx.message.text);
      if (!id) {
        return ctx.reply("Invalid user ID. Send a numeric Telegram user ID, or /cancel.");
      }

      if (isMainOwner(id) || (await globalOwnerSet()).has(id)) {
        await D.clearPending(db, ctx.from.id);
        return ctx.reply("That user is already the main owner or a global owner.");
      }

      await D.addGlobalOwner(db, id);
      globalOwnersCache = null;
      await D.clearPending(db, ctx.from.id);
      await logAction(ctx, "add_global_owner", Number(id));

      return ctx.reply(`Global owner ${id} has been added.`);
    }

    return next();
  });

  bot.command("joinhistory", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const entries = await D.getJoinHistory(db, ctx.chat.id, 15);

    if (!entries.length) {
      return ctx.reply(
        "No join history recorded yet. Only joins after the bot is installed can be tracked."
      );
    }

    await ctx.reply(
      "RECENT MEMBER JOINS\n\n" +
      entries.map((u, i) => `${i + 1}. ${u.name} (ID: ${u.user_id})\nJoined: ${u.joined_at}`).join("\n\n")
    );
  });

  // ======================== GROUP SETTINGS ========================
  async function toggleSetting(ctx, key, label) {
    if (!(await adminOnly(ctx))) return;

    const v = commandArgs(ctx).toLowerCase();
    if (!["on", "off"].includes(v)) {
      return ctx.reply(`Usage: /${key} on or /${key} off`);
    }

    await group(ctx); // make sure the group row exists
    await D.setGroupFlag(db, ctx.chat.id, key, v === "on");
    await logAction(ctx, `set_${key}`, null, { value: v });

    await ctx.reply(`${label} is now ${v.toUpperCase()}.`);
  }

  bot.command("welcome", ctx => toggleSetting(ctx, "welcome", "Welcome messages"));
  bot.command("antilink", ctx => toggleSetting(ctx, "antilink", "Anti-link protection"));
  bot.command("antiflood", ctx => toggleSetting(ctx, "antiflood", "Anti-flood protection"));

  bot.command("setrules", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const rules = commandArgs(ctx);
    if (!rules) {
      return ctx.reply("Usage: /setrules Be respectful and do not spam.");
    }

    await group(ctx);
    await D.setGroupRules(db, ctx.chat.id, rules.slice(0, 4000));
    await logAction(ctx, "set_rules");

    await ctx.reply("Group rules have been updated.");
  });

  bot.command("rules", async ctx => {
    if (!isGroup(ctx)) return ctx.reply("Use /rules in a group.");
    const g = await group(ctx);
    await ctx.reply(`GROUP RULES\n\n${g.rules}`);
  });

  // ======================== TIMED PROTECTION ========================
  for (const [cmd, type] of Object.entries(TIMED_COMMANDS)) {
    bot.command(cmd, async ctx => {
      if (!(await adminOnly(ctx))) return;

      const durationText = commandArgs(ctx).split(/\s+/)[0];
      const ms = parseDuration(durationText);

      if (!ms) {
        return ctx.reply(
          `Usage: /${cmd} 10m (valid durations: 30s, 10m, 2h, 1d; maximum 366 days).`
        );
      }

      await group(ctx);
      await D.setProtection(db, ctx.chat.id, type, Date.now() + ms, ctx.from.id);
      await logAction(ctx, `enable_${type}_protection`, null, { duration: durationText });

      await ctx.reply(`${type.toUpperCase()} protection enabled for ${durationText}.`);
    });
  }

  // ======================== MODERATION ========================
  bot.command("ban", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const u = repliedUser(ctx);
    if (!u) return ctx.reply("Reply to a member's message with /ban [reason].");
    if (!(await canModerateTarget(ctx, u))) return;

    const reason = commandArgs(ctx);

    try {
      await ctx.api.raw.banChatMember({ chat_id: ctx.chat.id, user_id: u.id });
      await logAction(ctx, "ban", u.id, { reason });
      await replyHtml(ctx, `🚫 ${mention(u)} has been banned.${withReason(reason)}`);
    } catch (e) {
      await ctx.reply(`Unable to ban this user. Check the bot's ban permission. (${errorText(e)})`);
    }
  });

  bot.command("unban", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const fromArgs = Number(commandArgs(ctx).split(/\s+/)[0]);
    const id = Number.isSafeInteger(fromArgs) && fromArgs > 0 ? fromArgs : repliedUser(ctx)?.id;

    if (!id) return ctx.reply("Usage: /unban USER_ID (or reply to the user).");

    try {
      await ctx.api.raw.unbanChatMember({ chat_id: ctx.chat.id, user_id: id, only_if_banned: true });
      await logAction(ctx, "unban", id);
      await ctx.reply(`User ${id} has been unbanned.`);
    } catch (e) {
      await ctx.reply(`Unable to unban this user. Check the ID and bot permissions. (${errorText(e)})`);
    }
  });

  bot.command("kick", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const u = repliedUser(ctx);
    if (!u) return ctx.reply("Reply to a member's message with /kick [reason].");
    if (!(await canModerateTarget(ctx, u))) return;

    const reason = commandArgs(ctx);

    try {
      await ctx.api.raw.banChatMember({ chat_id: ctx.chat.id, user_id: u.id });
      await ctx.api.raw.unbanChatMember({ chat_id: ctx.chat.id, user_id: u.id });

      await logAction(ctx, "kick", u.id, { reason });
      await replyHtml(ctx, `👢 ${mention(u)} has been removed from the group.${withReason(reason)}`);
    } catch (e) {
      await ctx.reply(`Unable to remove this user. Check the bot's permissions. (${errorText(e)})`);
    }
  });

  bot.command("mute", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const parts = commandArgs(ctx).split(/\s+/).filter(Boolean);
    const u = repliedUser(ctx);
    const ms = parseDuration(parts[0]);

    if (!u || !ms) {
      return ctx.reply("Reply to a member's message with /mute 10m [reason].");
    }
    if (!(await canModerateTarget(ctx, u))) return;

    const reason = parts.slice(1).join(" ");

    try {
      await ctx.api.raw.restrictChatMember({
        chat_id: ctx.chat.id,
        user_id: u.id,
        permissions: NO_SEND_PERMISSIONS,
        use_independent_chat_permissions: true,
        until_date: Math.floor((Date.now() + ms) / 1000)
      });

      await logAction(ctx, "mute", u.id, { duration: parts[0], reason });
      await replyHtml(ctx, `🔇 ${mention(u)} has been muted for ${esc(parts[0])}.${withReason(reason)}`);
    } catch (e) {
      await ctx.reply(`Unable to mute this user. Check the bot's restrict-members permission. (${errorText(e)})`);
    }
  });

  bot.command("unmute", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const u = repliedUser(ctx);
    if (!u) return ctx.reply("Reply to a member's message with /unmute.");
    if (!(await canModerateTarget(ctx, u))) return;

    try {
      await ctx.api.raw.restrictChatMember({
        chat_id: ctx.chat.id,
        user_id: u.id,
        permissions: await groupDefaultPermissions(ctx),
        use_independent_chat_permissions: true
      });

      await logAction(ctx, "unmute", u.id);
      await replyHtml(ctx, `🔊 ${mention(u)} has been unmuted.`);
    } catch (e) {
      await ctx.reply(`Unable to unmute this user. Check the bot's restrict-members permission. (${errorText(e)})`);
    }
  });

  bot.command("warn", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const u = repliedUser(ctx);
    if (!u) return ctx.reply("Reply to a member's message with /warn [reason].");
    if (!(await canModerateTarget(ctx, u))) return;

    const reason = commandArgs(ctx);

    await group(ctx);
    const count = await D.incrementWarning(db, ctx.chat.id, u.id);
    await logAction(ctx, "warn", u.id, { count, reason });

    if (count >= MAX_WARNINGS_BEFORE_BAN) {
      try {
        await ctx.api.raw.banChatMember({ chat_id: ctx.chat.id, user_id: u.id });
        await D.clearWarnings(db, ctx.chat.id, u.id);

        return replyHtml(
          ctx,
          `🚫 ${mention(u)} reached ${MAX_WARNINGS_BEFORE_BAN} warnings and has been banned.${withReason(reason)}`
        );
      } catch (e) {
        return ctx.reply(
          `Warning ${count}/${MAX_WARNINGS_BEFORE_BAN} issued. Automatic ban failed; check permissions. (${errorText(e)})`
        );
      }
    }

    await replyHtml(
      ctx,
      `⚠️ Warning ${count}/${MAX_WARNINGS_BEFORE_BAN} issued to ${mention(u)}.${withReason(reason)}`
    );
  });

  bot.command("resetwarn", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const u = repliedUser(ctx);
    if (!u) return ctx.reply("Reply to a member's message with /resetwarn.");

    await D.clearWarnings(db, ctx.chat.id, u.id);
    await logAction(ctx, "reset_warnings", u.id);
    await replyHtml(ctx, `Warnings have been reset for ${mention(u)}.`);
  });

  bot.command("pin", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const m = ctx.message.reply_to_message;
    if (!m) return ctx.reply("Reply to a message with /pin.");

    try {
      await ctx.api.raw.pinChatMessage({ chat_id: ctx.chat.id, message_id: m.message_id });
      await logAction(ctx, "pin", null, { messageId: m.message_id });
      await ctx.reply("Message pinned.");
    } catch (e) {
      await ctx.reply(`Unable to pin the message. Check the bot's pin permission. (${errorText(e)})`);
    }
  });

  bot.command("unpin", async ctx => {
    if (!(await adminOnly(ctx))) return;

    try {
      const replied = ctx.message.reply_to_message;
      const payload = { chat_id: ctx.chat.id };
      if (replied) payload.message_id = replied.message_id;

      await ctx.api.raw.unpinChatMessage(payload);
      await logAction(ctx, "unpin");
      await ctx.reply("Message unpinned.");
    } catch (e) {
      await ctx.reply(`Unable to unpin the message. Check the bot's pin permission. (${errorText(e)})`);
    }
  });

  bot.command("purge", async ctx => {
    if (!(await adminOnly(ctx))) return;

    const replied = ctx.message.reply_to_message;
    const argText = commandArgs(ctx).split(/\s+/)[0];
    const count = argText ? Number(argText) : 10;

    if (!replied && (!Number.isInteger(count) || count < 1 || count > 100)) {
      return ctx.reply(
        "Usage: /purge 1-100 to delete the last N messages, or reply to a message with /purge to delete everything from it onward (up to 100 messages)."
      );
    }

    const endId = ctx.message.message_id;
    const startId = replied
      ? Math.max(replied.message_id, endId - 99)
      : Math.max(1, endId - count);

    const ids = [];
    for (let id = startId; id <= endId; id++) ids.push(id);

    try {
      // Bulk deletion: one API call per 100 messages (keeps us far below the free-plan subrequest limit).
      for (let i = 0; i < ids.length; i += 100) {
        await ctx.api.raw.deleteMessages({ chat_id: ctx.chat.id, message_ids: ids.slice(i, i + 100) });
      }
    } catch (e) {
      return ctx.reply(`Unable to purge messages. Check the bot's delete-messages permission. (${errorText(e)})`);
    }

    await logAction(ctx, "purge", null, { requested: ids.length });
    await notify(
      ctx,
      `Purge complete. Requested deletion of ${ids.length} message(s). Messages older than 48 hours cannot be deleted by bots.`,
      5000
    );
  });

  bot.command("report", async ctx => {
    if (!isGroup(ctx)) return ctx.reply("Use /report in a group.");

    const m = ctx.message.reply_to_message;
    if (!m?.from) {
      return ctx.reply("Reply to the message you want to report, then send /report.");
    }

    const cooldownKey = `${ctx.chat.id}:${ctx.from.id}`;
    if (Date.now() - (reportCooldowns.get(cooldownKey) || 0) < REPORT_COOLDOWN_MS) {
      return ctx.reply("Please wait a moment before sending another report.");
    }
    reportCooldowns.set(cooldownKey, Date.now());

    await group(ctx);
    await D.addReport(db, {
      chatId: ctx.chat.id,
      groupTitle: ctx.chat.title,
      reporterId: ctx.from.id,
      targetId: m.from.id,
      messageId: m.message_id
    });

    const owners = new Set([
      mainOwnerId,
      ...(await globalOwnerSet()),
      ...(await D.listDelegatedOwners(db, ctx.chat.id))
    ]);

    for (const ownerId of [...owners].slice(0, MAX_REPORT_RECIPIENTS)) {
      try {
        await ctx.api.raw.sendMessage({
          chat_id: Number(ownerId),
          text:
            `NEW GROUP REPORT\nGroup: ${ctx.chat.title}\n` +
            `Reporter ID: ${ctx.from.id}\nReported user ID: ${m.from.id}\n` +
            `Message ID: ${m.message_id}`
        });
      } catch {
        // The owner may not have started the bot in private.
      }
    }

    await ctx.reply("Your report has been recorded for administrator review.");
  });

  // ======================== ERROR HANDLING ========================
  bot.catch(err => {
    console.error(
      `Update ${err.ctx?.update?.update_id ?? "unknown"} failed:`,
      errorText(err.error)
    );
  });

  return bot;
}
