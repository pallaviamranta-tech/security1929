/**
 * D1 data access layer for 18n28 Security Bot.
 * Every function receives the D1 binding (env.DB) as its first argument.
 */
import {
  DEFAULT_RULES, DEFAULT_SETTINGS, MAX_HISTORY, MAX_AUDIT_LOGS, MAX_REPORTS, JOIN_DEDUPE_MS
} from "./config.js";
import { displayName } from "./util.js";

const FLAG_COLUMNS = new Set(["welcome", "antilink", "antiflood"]);

function parseJson(text, fallback) {
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value : fallback;
  } catch {
    return fallback;
  }
}

/** Read one group together with its protections and owner lists (single round trip). */
async function readGroup(db, chatId) {
  const [groupRes, protRes, delegatedRes, globalRes] = await db.batch([
    db.prepare(
      `SELECT chat_id, title, added_by, rules, welcome, antilink, antiflood, extra_settings
         FROM chat_groups WHERE chat_id = ?1`
    ).bind(chatId),
    db.prepare("SELECT type, until_ms, set_by FROM group_protections WHERE chat_id = ?1").bind(chatId),
    db.prepare("SELECT user_id FROM delegated_owners WHERE chat_id = ?1").bind(chatId),
    db.prepare("SELECT user_id FROM global_owners")
  ]);

  const row = groupRes.results[0];
  if (!row) return null;

  const protection = {};
  for (const p of protRes.results) {
    protection[p.type] = { until: Number(p.until_ms), by: p.set_by };
  }

  return {
    id: Number(row.chat_id),
    title: row.title || "Group",
    addedBy: row.added_by ?? null,
    rawRules: row.rules || "",
    rules: row.rules || DEFAULT_RULES,
    settings: {
      ...DEFAULT_SETTINGS,
      welcome: row.welcome === 1,
      antilink: row.antilink === 1,
      antiflood: row.antiflood === 1
    },
    extraSettings: parseJson(row.extra_settings, {}),
    protection,
    delegatedOwners: new Set(delegatedRes.results.map(r => String(r.user_id))),
    globalOwners: new Set(globalRes.results.map(r => String(r.user_id)))
  };
}

/** Load a group, creating its row on first sight and keeping the title up to date. */
export async function loadGroup(db, chat) {
  let state = await readGroup(db, chat.id);

  if (!state) {
    await db.prepare("INSERT OR IGNORE INTO chat_groups (chat_id, title) VALUES (?1, ?2)")
      .bind(chat.id, chat.title || "Group").run();
    state = await readGroup(db, chat.id);
  } else if (chat.title && chat.title !== state.title) {
    await db.prepare(
      `UPDATE chat_groups SET title = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE chat_id = ?1`
    ).bind(chat.id, chat.title).run();
    state.title = chat.title;
  }

  return state;
}

export function getGroupById(db, chatId) {
  return readGroup(db, chatId);
}

// ---------- owners ----------
export async function listGlobalOwners(db) {
  const res = await db.prepare("SELECT user_id FROM global_owners").all();
  return new Set(res.results.map(r => String(r.user_id)));
}

export async function addGlobalOwner(db, userId) {
  await db.prepare("INSERT OR IGNORE INTO global_owners (user_id) VALUES (?1)").bind(Number(userId)).run();
}

export async function listDelegatedOwners(db, chatId) {
  const res = await db.prepare("SELECT user_id FROM delegated_owners WHERE chat_id = ?1").bind(chatId).all();
  return res.results.map(r => String(r.user_id));
}

/** Groups visible to an owner in the private dashboard (at most 30, like the original bot). */
export async function groupsForOwner(db, userId, isGlobal) {
  const res = isGlobal
    ? await db.prepare(
        "SELECT chat_id, title FROM chat_groups ORDER BY title COLLATE NOCASE LIMIT 30"
      ).all()
    : await db.prepare(
        `SELECT g.chat_id, g.title FROM chat_groups g
          WHERE g.added_by = ?1
             OR EXISTS (SELECT 1 FROM delegated_owners d WHERE d.chat_id = g.chat_id AND d.user_id = ?1)
          ORDER BY g.title COLLATE NOCASE LIMIT 30`
      ).bind(Number(userId)).all();

  return res.results.map(r => ({ id: Number(r.chat_id), title: r.title }));
}

// ---------- group settings ----------
export async function setGroupFlag(db, chatId, column, value) {
  if (!FLAG_COLUMNS.has(column)) throw new Error(`Unknown setting: ${column}`);
  await db.prepare(
    `UPDATE chat_groups SET ${column} = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE chat_id = ?1`
  ).bind(chatId, value ? 1 : 0).run();
}

export async function setGroupRules(db, chatId, rules) {
  await db.prepare(
    `UPDATE chat_groups SET rules = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE chat_id = ?1`
  ).bind(chatId, rules).run();
}

export async function setGroupAddedBy(db, chatId, userId) {
  await db.prepare("UPDATE chat_groups SET added_by = COALESCE(?2, added_by) WHERE chat_id = ?1")
    .bind(chatId, userId ?? null).run();
}

// ---------- timed protections ----------
export async function setProtection(db, chatId, type, untilMs, setBy) {
  await db.batch([
    db.prepare("DELETE FROM group_protections WHERE until_ms <= ?1").bind(Date.now()),
    db.prepare(
      `INSERT INTO group_protections (chat_id, type, until_ms, set_by) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(chat_id, type) DO UPDATE SET until_ms = excluded.until_ms, set_by = excluded.set_by`
    ).bind(chatId, type, untilMs, setBy ?? null)
  ]);
}

// ---------- warnings ----------
/** Atomically add one warning and return the new count. */
export async function incrementWarning(db, chatId, userId) {
  const row = await db.prepare(
    `INSERT INTO warnings (chat_id, user_id, count) VALUES (?1, ?2, 1)
     ON CONFLICT(chat_id, user_id) DO UPDATE SET count = count + 1
     RETURNING count`
  ).bind(chatId, userId).first();
  return Number(row.count);
}

export async function clearWarnings(db, chatId, userId) {
  await db.prepare("DELETE FROM warnings WHERE chat_id = ?1 AND user_id = ?2").bind(chatId, userId).run();
}

// ---------- join history ----------
/**
 * Record a join. Returns false when the same member was already recorded within the last
 * few seconds (the same join can arrive as both a chat_member update and a service message).
 */
export async function recordJoin(db, chatId, user, actorId) {
  const joinedAt = new Date().toISOString();
  const cutoff = new Date(Date.now() - JOIN_DEDUPE_MS).toISOString();
  const name = displayName(user);
  const username = user.username || null;

  const inserted = await db.prepare(
    `INSERT INTO join_history (chat_id, user_id, name, username, joined_at, added_by)
     SELECT ?1, ?2, ?3, ?4, ?5, ?6
      WHERE NOT EXISTS (
        SELECT 1 FROM join_history WHERE chat_id = ?1 AND user_id = ?2 AND joined_at > ?7
      )`
  ).bind(chatId, user.id, name, username, joinedAt, actorId ?? null, cutoff).run();

  if (!inserted.meta?.changes) return false;

  await db.batch([
    db.prepare(
      `INSERT INTO users (user_id, name, username, last_seen_at) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(user_id) DO UPDATE SET
         name = excluded.name, username = excluded.username, last_seen_at = excluded.last_seen_at`
    ).bind(user.id, name, username, joinedAt),
    db.prepare(
      `INSERT INTO members (chat_id, user_id, name, username) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(chat_id, user_id) DO UPDATE SET name = excluded.name, username = excluded.username`
    ).bind(chatId, user.id, name, username),
    db.prepare(
      `DELETE FROM join_history
        WHERE chat_id = ?1
          AND id IN (SELECT id FROM join_history WHERE chat_id = ?1 ORDER BY id DESC LIMIT -1 OFFSET ?2)`
    ).bind(chatId, MAX_HISTORY)
  ]);

  return true;
}

export async function getJoinHistory(db, chatId, limit = 15) {
  const res = await db.prepare(
    "SELECT user_id, name, joined_at FROM join_history WHERE chat_id = ?1 ORDER BY id DESC LIMIT ?2"
  ).bind(chatId, limit).all();
  return res.results;
}

// ---------- audit log and reports ----------
export async function logAction(db, { chatId, actorId, targetId, action, extra }) {
  await db.batch([
    db.prepare(
      `INSERT INTO audit_logs (chat_id, actor_id, target_id, action, extra, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
    ).bind(chatId ?? null, actorId ?? null, targetId ?? null, action, JSON.stringify(extra || {}), new Date().toISOString()),
    db.prepare("DELETE FROM audit_logs WHERE id <= (SELECT MAX(id) FROM audit_logs) - ?1").bind(MAX_AUDIT_LOGS)
  ]);
}

export async function addReport(db, { chatId, groupTitle, reporterId, targetId, messageId }) {
  await db.batch([
    db.prepare(
      `INSERT INTO reports (chat_id, group_title, reporter_id, target_id, message_id, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
    ).bind(chatId, groupTitle ?? null, reporterId, targetId, messageId, new Date().toISOString()),
    db.prepare("DELETE FROM reports WHERE id <= (SELECT MAX(id) FROM reports) - ?1").bind(MAX_REPORTS)
  ]);
}

// ---------- pending private actions ----------
export async function setPending(db, userId, type, expiresAt) {
  await db.batch([
    db.prepare("DELETE FROM pending_actions WHERE expires_at < ?1").bind(Date.now()),
    db.prepare(
      `INSERT INTO pending_actions (user_id, type, expires_at) VALUES (?1, ?2, ?3)
       ON CONFLICT(user_id) DO UPDATE SET type = excluded.type, expires_at = excluded.expires_at`
    ).bind(Number(userId), type, expiresAt)
  ]);
}

export function getPending(db, userId) {
  return db.prepare("SELECT type, expires_at FROM pending_actions WHERE user_id = ?1")
    .bind(Number(userId)).first();
}

export async function clearPending(db, userId) {
  await db.prepare("DELETE FROM pending_actions WHERE user_id = ?1").bind(Number(userId)).run();
}
