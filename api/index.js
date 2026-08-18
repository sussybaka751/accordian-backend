const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();

const FIREBASE_DB_URL = (process.env.FIREBASE_DB_URL || "https://my-chat-app-8642f-default-rtdb.firebaseio.com").replace(/\/+$/, "");
const FIREBASE_AUTH_SECRET = process.env.FIREBASE_AUTH_SECRET || "";
const JWT_SECRET = process.env.JWT_SECRET || "accordian-super-secret-jwt-key-2026-change-me";
const DEV_USERS = ["speezely", "$@g3"];
const DEFAULT_BANNER = "#5865f2";
const PRESENCE_TIMEOUT_MS = 45 * 1000;
const TYPING_TIMEOUT_MS = 6 * 1000;

// CORS – allow everything for now (you can lock this later to your frontend domain)
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));
app.use(express.json({ limit: '50mb' }));

// ---------- Firebase REST Client ----------
class FirebaseClient {
  constructor(baseUrl, secret) {
    this.baseUrl = baseUrl;
    this.secret = secret;
  }

  buildUrl(path, queryParams = {}) {
    const cleanPath = path.startsWith('/') ? path.slice(1) : path;
    const url = new URL(`${this.baseUrl}/${cleanPath}.json`);
    if (this.secret) url.searchParams.set('auth', this.secret);
    for (const [k, v] of Object.entries(queryParams)) {
      if (v !== undefined && v !== null) {
        url.searchParams.set(k, typeof v === 'object' ? JSON.stringify(v) : String(v));
      }
    }
    return url.toString();
  }

  async get(path, params = {}) {
    const res = await fetch(this.buildUrl(path, params));
    if (!res.ok) throw new Error(`Firebase GET ${path} error: ${res.statusText}`);
    return res.json();
  }

  async set(path, data) {
    const res = await fetch(this.buildUrl(path), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Firebase PUT ${path} error: ${res.statusText}`);
    return res.json();
  }

  async push(path, data) {
    const res = await fetch(this.buildUrl(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Firebase POST ${path} error: ${res.statusText}`);
    return res.json();
  }

  async update(path, data) {
    const res = await fetch(this.buildUrl(path), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Firebase PATCH ${path} error: ${res.statusText}`);
    return res.json();
  }

  async remove(path) {
    const res = await fetch(this.buildUrl(path), { method: 'DELETE' });
    if (!res.ok) throw new Error(`Firebase DELETE ${path} error: ${res.statusText}`);
    return res.json();
  }
}

const fb = new FirebaseClient(FIREBASE_DB_URL, FIREBASE_AUTH_SECRET);

// ---------- Helpers ----------
function sanitizeKey(k) {
  if (!k) return "";
  return String(k).toLowerCase().replace(/[.#$/\[\]]/g, "_");
}

function isDev(username) {
  return username && DEV_USERS.includes(username.toLowerCase());
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256').toString('hex');
}

function cleanUserProfile(u) {
  if (!u) return null;
  const { password, passwordHash, salt, ...safeProfile } = u;
  return safeProfile;
}

function getUserServerRole(server, username) {
  if (!server || !username) return null;
  if (server.creator && server.creator.toLowerCase() === username.toLowerCase()) return "creator";
  const san = sanitizeKey(username);
  if (server.members && server.members[san]) return server.members[san].role || "member";
  return null;
}

function canManageServer(server, username) {
  if (isDev(username)) return true;
  const role = getUserServerRole(server, username);
  return role === "creator" || role === "co-creator";
}

function canManageGroup(group, username) {
  if (!group || !username) return false;
  if (isDev(username)) return true;
  if (group.creator) return group.creator.toLowerCase() === username.toLowerCase();
  const members = group.members || [];
  return members[0] && members[0].toLowerCase() === username.toLowerCase();
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.query.token;
  if (!token) return res.status(401).json({ error: "Unauthorized. Token missing.", success: false });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.username = decoded.sub;
    req.sanitizedUser = sanitizeKey(req.username);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token.", success: false });
  }
}

// ---------- Health ----------
app.get(['/', '/api/health', '/health'], (req, res) => {
  res.json({
    status: "online",
    service: "Accordian Backend (Render)",
    version: "2.0.0",
    message: "Backend is running smoothly 24/7!"
  });
});

// ---------- Auth ----------
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required.", success: false });
    if (username.trim().length < 2) return res.status(400).json({ error: "Username too short.", success: false });

    const san = sanitizeKey(username);
    const existing = await fb.get(`users/${san}`);
    if (existing) return res.status(409).json({ error: "Username is already taken.", success: false });

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(password, salt);

    const newUser = {
      username: username.trim(),
      passwordHash,
      salt,
      bio: "",
      pronouns: "",
      banner_color: DEFAULT_BANNER,
      avatar_url: "",
      created_at: new Date().toISOString()
    };

    await fb.set(`users/${san}`, newUser);
    const token = jwt.sign({ sub: newUser.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: cleanUserProfile(newUser) });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required.", success: false });

    const san = sanitizeKey(username);
    const user = await fb.get(`users/${san}`);
    if (!user) return res.status(401).json({ error: "Invalid username or password.", success: false });

    let isValid = false;
    if (user.passwordHash && user.salt) {
      isValid = hashPassword(password, user.salt) === user.passwordHash;
    } else if (user.password) {
      // Legacy plaintext migration
      if (user.password === password) {
        isValid = true;
        const newSalt = crypto.randomBytes(16).toString('hex');
        const newHash = hashPassword(password, newSalt);
        await fb.update(`users/${san}`, { passwordHash: newHash, salt: newSalt, password: null }).catch(() => {});
      }
    }

    if (!isValid) return res.status(401).json({ error: "Invalid username or password.", success: false });

    const token = jwt.sign({ sub: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: cleanUserProfile(user) });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await fb.get(`users/${req.sanitizedUser}`);
    if (!user) return res.status(404).json({ error: "User not found.", success: false });
    res.json({ success: true, user: cleanUserProfile(user) });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Users ----------
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const users = (await fb.get("users")) || {};
    const safeProfiles = {};
    for (const [k, u] of Object.entries(users)) {
      if (u && u.username) safeProfiles[u.username.toLowerCase()] = cleanUserProfile(u);
    }
    res.json({ success: true, users: safeProfiles });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.patch('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    const updates = {};
    if (req.body.bio !== undefined) updates.bio = String(req.body.bio).slice(0, 500);
    if (req.body.pronouns !== undefined) updates.pronouns = String(req.body.pronouns).slice(0, 30);
    if (req.body.banner_color !== undefined) updates.banner_color = String(req.body.banner_color).slice(0, 25);
    if (req.body.avatar_url !== undefined) updates.avatar_url = req.body.avatar_url;

    await fb.update(`users/${req.sanitizedUser}`, updates);
    const updated = await fb.get(`users/${req.sanitizedUser}`);
    res.json({ success: true, user: cleanUserProfile(updated) });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/users/:username/tag', authMiddleware, async (req, res) => {
  try {
    if (!isDev(req.username)) return res.status(403).json({ error: "Dev only.", success: false });
    const targetSan = sanitizeKey(req.params.username);
    if (req.body.remove) {
      await fb.update(`users/${targetSan}`, { customTag: null });
    } else {
      if (!req.body.text) return res.status(400).json({ error: "Text required.", success: false });
      await fb.update(`users/${targetSan}`, {
        customTag: { text: String(req.body.text).slice(0, 20), color: req.body.color || "#00e5ff" }
      });
    }
    res.json({ success: true, message: "Tag updated." });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Presence ----------
app.post('/api/presence/heartbeat', authMiddleware, async (req, res) => {
  try {
    const now = Date.now();
    const connId = req.body.connectionId || "default";
    await fb.update(`status/${req.sanitizedUser}`, {
      state: "online",
      lastPing: now,
      [`connections/${connId}`]: now
    });
    res.json({ success: true, timestamp: now });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/presence/offline', authMiddleware, async (req, res) => {
  try {
    await fb.set(`status/${req.sanitizedUser}`, {
      state: "offline",
      lastOnline: Date.now(),
      connections: null
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.get('/api/presence', authMiddleware, async (req, res) => {
  try {
    const statuses = (await fb.get("status")) || {};
    const now = Date.now();
    const computed = {};
    for (const [k, val] of Object.entries(statuses)) {
      if (!val) continue;
      const active =
        (val.connections && Object.values(val.connections).some(ts => now - Number(ts) < PRESENCE_TIMEOUT_MS)) ||
        (val.lastPing && now - Number(val.lastPing) < PRESENCE_TIMEOUT_MS);
      computed[k] = active ? "online" : "offline";
    }
    res.json({ success: true, statuses: computed });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Typing ----------
app.post('/api/typing', authMiddleware, async (req, res) => {
  try {
    const { typingKey, isTyping } = req.body;
    if (!typingKey) return res.status(400).json({ error: "typingKey required.", success: false });
    const cleanKey = sanitizeKey(typingKey);
    if (isTyping) await fb.set(`typing/${cleanKey}/${req.sanitizedUser}`, Date.now());
    else await fb.remove(`typing/${cleanKey}/${req.sanitizedUser}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.get('/api/typing', authMiddleware, async (req, res) => {
  try {
    const typingKey = req.query.typingKey;
    if (!typingKey) return res.status(400).json({ error: "typingKey required.", success: false });
    const typers = (await fb.get(`typing/${sanitizeKey(typingKey)}`)) || {};
    const now = Date.now();
    const active = Object.entries(typers)
      .filter(([uSan, ts]) => now - Number(ts) < TYPING_TIMEOUT_MS && uSan !== req.sanitizedUser)
      .map(([uSan]) => uSan);
    res.json({ success: true, typers: active });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Messages ----------
app.get('/api/messages', authMiddleware, async (req, res) => {
  try {
    const targetDm = req.query.target_dm || "";
    const limit = Math.min(Number(req.query.limit || 80), 200);
    const msgs = (await fb.get("messages", { limitToLast: limit, orderBy: '"created_at"' })) || {};
    let list = Object.entries(msgs).map(([id, val]) => ({ id, ...val }));
    if (targetDm) list = list.filter(m => (m.target_dm || "").toLowerCase() === targetDm.toLowerCase());
    list.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    res.json({ success: true, messages: list });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { message, target_dm, reply_to, client_id } = req.body;
    if (!message || !target_dm) return res.status(400).json({ error: "Message & target_dm required.", success: false });

    if (target_dm.startsWith("server:")) {
      const [, sId, chId] = target_dm.split(":");
      const server = await fb.get(`servers/${sId}`);
      if (!server) return res.status(404).json({ error: "Server not found.", success: false });
      const ch = server.channels?.[chId];
      if (ch?.isEditorOnly) {
        const role = getUserServerRole(server, req.username);
        const canPost = ["creator", "co-creator", "editor"].includes(role) || isDev(req.username);
        if (!canPost) return res.status(403).json({ error: "Channel locked to Editors/Creators.", success: false });
      }
    }

    if (target_dm.startsWith("group:")) {
      const gId = target_dm.split(":")[1];
      const group = await fb.get(`groups/${gId}`);
      if (!group) return res.status(404).json({ error: "Group not found.", success: false });
      const isMember = (group.members || []).some(m => m && m.toLowerCase() === req.username.toLowerCase()) || isDev(req.username);
      if (!isMember) return res.status(403).json({ error: "Not a group member.", success: false });
    }

    const newMsg = {
      username: req.username,
      message,
      target_dm,
      reply_to: reply_to || "",
      client_id: client_id || "srv_" + Date.now(),
      created_at: new Date().toISOString()
    };

    const pushRes = await fb.push("messages", newMsg);
    newMsg.id = pushRes.name;
    res.json({ success: true, message: newMsg });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.patch('/api/messages/:id', authMiddleware, async (req, res) => {
  try {
    const msg = await fb.get(`messages/${req.params.id}`);
    if (!msg) return res.status(404).json({ error: "Message not found.", success: false });
    if (msg.username.toLowerCase() !== req.username.toLowerCase() && !isDev(req.username)) {
      return res.status(403).json({ error: "Can only edit own messages.", success: false });
    }
    await fb.update(`messages/${req.params.id}`, {
      message: req.body.message,
      is_edited: true,
      edited_at: new Date().toISOString()
    });
    res.json({ success: true, message: { ...msg, message: req.body.message, is_edited: true } });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.delete('/api/messages/:id', authMiddleware, async (req, res) => {
  try {
    const msg = await fb.get(`messages/${req.params.id}`);
    if (!msg) return res.status(404).json({ error: "Message not found.", success: false });
    if (msg.username.toLowerCase() !== req.username.toLowerCase() && !isDev(req.username)) {
      return res.status(403).json({ error: "Forbidden.", success: false });
    }
    await fb.remove(`messages/${req.params.id}`);
    res.json({ success: true, messageId: req.params.id });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/messages/:id/reactions', authMiddleware, async (req, res) => {
  try {
    const { emoji } = req.body;
    if (!emoji) return res.status(400).json({ error: "Emoji required.", success: false });
    const cleanEmoji = encodeURIComponent(emoji);
    const existing = (await fb.get(`messages/${req.params.id}/reactions/${cleanEmoji}`)) || [];
    let list = Array.isArray(existing) ? existing : Object.values(existing);
    const idx = list.findIndex(u => (typeof u === "string" ? u : u.username || "").toLowerCase() === req.username.toLowerCase());
    if (idx !== -1) list.splice(idx, 1);
    else list.push(req.username);
    if (list.length === 0) await fb.remove(`messages/${req.params.id}/reactions/${cleanEmoji}`);
    else await fb.set(`messages/${req.params.id}/reactions/${cleanEmoji}`, list);
    res.json({ success: true, emoji, users: list });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Groups ----------
app.get('/api/groups', authMiddleware, async (req, res) => {
  try {
    const groups = (await fb.get("groups")) || {};
    const myGroups = {};
    for (const [gId, g] of Object.entries(groups)) {
      if (g && ((g.members || []).some(m => m && m.toLowerCase() === req.username.toLowerCase()) || isDev(req.username))) {
        myGroups[gId] = g;
      }
    }
    res.json({ success: true, groups: myGroups });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/groups', authMiddleware, async (req, res) => {
  try {
    let members = req.body.members || [];
    if (!Array.isArray(members)) members = [];
    if (!members.some(m => m && m.toLowerCase() === req.username.toLowerCase())) members.unshift(req.username);
    if (members.length < 2) return res.status(400).json({ error: "At least 2 members required.", success: false });

    const newGroup = {
      name: req.body.name ? String(req.body.name).slice(0, 40) : "",
      icon: req.body.icon || "",
      creator: req.username,
      members,
      created_at: new Date().toISOString()
    };
    const pushRes = await fb.push("groups", newGroup);
    res.json({ success: true, groupId: pushRes.name, group: newGroup });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.patch('/api/groups/:id', authMiddleware, async (req, res) => {
  try {
    const group = await fb.get(`groups/${req.params.id}`);
    if (!group) return res.status(404).json({ error: "Group not found.", success: false });
    if (!canManageGroup(group, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });

    const updates = {};
    if (req.body.name !== undefined) updates.name = String(req.body.name).slice(0, 40);
    if (req.body.icon !== undefined) updates.icon = req.body.icon;
    await fb.update(`groups/${req.params.id}`, updates);
    res.json({ success: true, updated: updates });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/groups/:id/members', authMiddleware, async (req, res) => {
  try {
    const group = await fb.get(`groups/${req.params.id}`);
    if (!group) return res.status(404).json({ error: "Group not found.", success: false });
    if (!canManageGroup(group, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });

    const targetUser = req.body.username;
    if (!targetUser) return res.status(400).json({ error: "Username required.", success: false });
    const members = group.members || [];
    if (members.some(m => m.toLowerCase() === targetUser.toLowerCase())) {
      return res.status(409).json({ error: "Already in group.", success: false });
    }
    members.push(targetUser);
    await fb.update(`groups/${req.params.id}`, { members });
    res.json({ success: true, members });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.delete('/api/groups/:id/members/:username', authMiddleware, async (req, res) => {
  try {
    const group = await fb.get(`groups/${req.params.id}`);
    if (!group) return res.status(404).json({ error: "Group not found.", success: false });
    const isSelf = req.params.username.toLowerCase() === req.username.toLowerCase();
    if (!isSelf && !canManageGroup(group, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });

    const members = (group.members || []).filter(m => m.toLowerCase() !== req.params.username.toLowerCase());
    await fb.update(`groups/${req.params.id}`, { members });
    res.json({ success: true, members });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.delete('/api/groups/:id', authMiddleware, async (req, res) => {
  try {
    const group = await fb.get(`groups/${req.params.id}`);
    if (!group) return res.status(404).json({ error: "Group not found.", success: false });
    if (!canManageGroup(group, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });
    await fb.remove(`groups/${req.params.id}`);
    res.json({ success: true, groupId: req.params.id });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Servers & Channels ----------
app.get('/api/servers', authMiddleware, async (req, res) => {
  try {
    const servers = (await fb.get("servers")) || {};
    const accessible = {};
    for (const [sId, s] of Object.entries(servers)) {
      if (s && (getUserServerRole(s, req.username) || isDev(req.username) || s.forced)) {
        accessible[sId] = s;
      }
    }
    res.json({ success: true, servers: accessible });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/servers', authMiddleware, async (req, res) => {
  try {
    if (!req.body.name) return res.status(400).json({ error: "Server name required.", success: false });
    const newServer = {
      name: String(req.body.name).slice(0, 50),
      icon: req.body.icon || "",
      creator: req.username,
      forced: false,
      created_at: new Date().toISOString(),
      members: { [req.sanitizedUser]: { username: req.username, role: "creator" } },
      channels: { general: { name: "general", isEditorOnly: false } }
    };
    const pushRes = await fb.push("servers", newServer);
    res.json({ success: true, serverId: pushRes.name, server: newServer });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.patch('/api/servers/:id', authMiddleware, async (req, res) => {
  try {
    const server = await fb.get(`servers/${req.params.id}`);
    if (!server) return res.status(404).json({ error: "Server not found.", success: false });

    const updates = {};
    if (req.body.forced !== undefined) {
      if (!isDev(req.username)) return res.status(403).json({ error: "Dev only.", success: false });
      updates.forced = Boolean(req.body.forced);
    }
    if (req.body.name !== undefined || req.body.icon !== undefined) {
      if (!canManageServer(server, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });
      if (req.body.name !== undefined) updates.name = String(req.body.name).slice(0, 50);
      if (req.body.icon !== undefined) updates.icon = req.body.icon;
    }
    await fb.update(`servers/${req.params.id}`, updates);
    res.json({ success: true, updated: updates });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.delete('/api/servers/:id', authMiddleware, async (req, res) => {
  try {
    const server = await fb.get(`servers/${req.params.id}`);
    if (!server) return res.status(404).json({ error: "Server not found.", success: false });
    if (server.creator?.toLowerCase() !== req.username.toLowerCase() && !isDev(req.username)) {
      return res.status(403).json({ error: "Forbidden.", success: false });
    }
    await fb.remove(`servers/${req.params.id}`);
    res.json({ success: true, serverId: req.params.id });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/servers/:id/join', authMiddleware, async (req, res) => {
  try {
    await fb.set(`servers/${req.params.id}/members/${req.sanitizedUser}`, {
      username: req.username,
      role: "member"
    });
    res.json({ success: true, role: "member" });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/servers/:id/members', authMiddleware, async (req, res) => {
  try {
    const server = await fb.get(`servers/${req.params.id}`);
    if (!server) return res.status(404).json({ error: "Server not found.", success: false });
    const role = getUserServerRole(server, req.username);
    if (!["creator", "co-creator", "editor"].includes(role) && !isDev(req.username)) {
      return res.status(403).json({ error: "Forbidden.", success: false });
    }
    const targetUser = req.body.username;
    if (!targetUser) return res.status(400).json({ error: "Username required.", success: false });
    await fb.set(`servers/${req.params.id}/members/${sanitizeKey(targetUser)}`, {
      username: targetUser,
      role: req.body.role || "member"
    });
    res.json({ success: true, username: targetUser });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.patch('/api/servers/:id/members/:username/role', authMiddleware, async (req, res) => {
  try {
    const server = await fb.get(`servers/${req.params.id}`);
    if (!server) return res.status(404).json({ error: "Server not found.", success: false });
    if (!canManageServer(server, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });
    await fb.update(`servers/${req.params.id}/members/${sanitizeKey(req.params.username)}`, {
      role: req.body.role || "member"
    });
    res.json({ success: true, role: req.body.role });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.delete('/api/servers/:id/members/:username', authMiddleware, async (req, res) => {
  try {
    const server = await fb.get(`servers/${req.params.id}`);
    if (!server) return res.status(404).json({ error: "Server not found.", success: false });
    const isSelf = req.params.username.toLowerCase() === req.username.toLowerCase();
    if (!isSelf && !canManageServer(server, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });
    await fb.remove(`servers/${req.params.id}/members/${sanitizeKey(req.params.username)}`);
    res.json({ success: true, kicked: req.params.username });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// Channels
app.post('/api/servers/:id/channels', authMiddleware, async (req, res) => {
  try {
    const server = await fb.get(`servers/${req.params.id}`);
    if (!server) return res.status(404).json({ error: "Server not found.", success: false });
    if (!canManageServer(server, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });

    const rawName = (req.body.name || "").trim().toLowerCase().replace(/[\s#]/g, "-");
    if (!rawName) return res.status(400).json({ error: "Name required.", success: false });
    const data = { name: rawName, isEditorOnly: Boolean(req.body.isEditorOnly) };
    await fb.set(`servers/${req.params.id}/channels/${rawName}`, data);
    res.json({ success: true, channelId: rawName, channel: data });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.patch('/api/servers/:id/channels/:channelId', authMiddleware, async (req, res) => {
  try {
    const server = await fb.get(`servers/${req.params.id}`);
    if (!server) return res.status(404).json({ error: "Server not found.", success: false });
    if (!canManageServer(server, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });

    const newName = req.body.name
      ? req.body.name.trim().toLowerCase().replace(/[\s#]/g, "-")
      : req.params.channelId;
    const isEditorOnly = req.body.isEditorOnly !== undefined ? Boolean(req.body.isEditorOnly) : false;

    if (newName !== req.params.channelId) {
      await fb.set(`servers/${req.params.id}/channels/${newName}`, { name: newName, isEditorOnly });
      await fb.remove(`servers/${req.params.id}/channels/${req.params.channelId}`);
    } else {
      await fb.update(`servers/${req.params.id}/channels/${req.params.channelId}`, { isEditorOnly });
    }
    res.json({ success: true, channelId: newName });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.delete('/api/servers/:id/channels/:channelId', authMiddleware, async (req, res) => {
  try {
    const server = await fb.get(`servers/${req.params.id}`);
    if (!server) return res.status(404).json({ error: "Server not found.", success: false });
    if (!canManageServer(server, req.username)) return res.status(403).json({ error: "Forbidden.", success: false });
    await fb.remove(`servers/${req.params.id}/channels/${req.params.channelId}`);
    res.json({ success: true, channelId: req.params.channelId });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Announcements ----------
app.get('/api/announcements', authMiddleware, async (req, res) => {
  try {
    const announcements = (await fb.get("announcements")) || {};
    const list = Object.entries(announcements).map(([id, val]) => ({ id, ...val }));
    list.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json({ success: true, announcements: list });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/announcements', authMiddleware, async (req, res) => {
  try {
    if (!isDev(req.username)) return res.status(403).json({ error: "Dev only.", success: false });
    if (!req.body.message) return res.status(400).json({ error: "Message required.", success: false });
    const newAnn = {
      username: req.username,
      message: String(req.body.message),
      created_at: new Date().toISOString()
    };
    const pushRes = await fb.push("announcements", newAnn);
    res.json({ success: true, announcementId: pushRes.name, announcement: newAnn });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- WebRTC / Calls ----------
app.get('/api/calls', authMiddleware, async (req, res) => {
  try {
    const calls = (await fb.get("calls")) || {};
    const myActive = {};
    const myLow = req.username.toLowerCase();
    for (const [cId, c] of Object.entries(calls)) {
      if (!c || c.status === "ended") continue;
      const isPart =
        c.caller?.toLowerCase() === myLow ||
        c.callee?.toLowerCase() === myLow ||
        (Array.isArray(c.participants) && c.participants.some(p => p.toLowerCase() === myLow));
      if (isPart) myActive[cId] = c;
    }
    res.json({ success: true, calls: myActive });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/calls/start', authMiddleware, async (req, res) => {
  try {
    const callType = req.body.type === "group" ? "group" : "dm";
    const callId = (callType === "group" ? "gcall_" : "call_") + Date.now() + "_" + Math.floor(Math.random() * 1000);
    let callData = {};

    if (callType === "group") {
      const group = await fb.get(`groups/${req.body.groupId}`);
      if (!group) return res.status(404).json({ error: "Group not found.", success: false });
      callData = {
        type: "group",
        groupId: req.body.groupId,
        caller: req.username,
        participants: group.members || [req.username],
        joined: { [req.sanitizedUser]: true },
        status: "active",
        started_at: new Date().toISOString(),
        created_at: new Date().toISOString()
      };
    } else {
      callData = {
        caller: req.username,
        callee: req.body.callee,
        status: "ringing",
        created_at: new Date().toISOString()
      };
    }

    await fb.set(`calls/${callId}`, callData);

    if (req.body.target_dm) {
      await fb.push("messages", {
        username: req.username,
        message: `[VIDEOCALL:${callId}]`,
        target_dm: req.body.target_dm,
        reply_to: "",
        client_id: callId,
        created_at: new Date().toISOString()
      });
    }

    res.json({ success: true, callId, call: callData });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.get('/api/calls/:id', authMiddleware, async (req, res) => {
  try {
    const call = await fb.get(`calls/${req.params.id}`);
    if (!call) return res.status(404).json({ error: "Call not found.", success: false });
    res.json({ success: true, call });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/calls/:id/status', authMiddleware, async (req, res) => {
  try {
    const updates = { status: req.body.status };
    if (req.body.status === "active") updates.started_at = new Date().toISOString();
    if (req.body.status === "ended") updates.ended_at = new Date().toISOString();
    await fb.update(`calls/${req.params.id}`, updates);
    res.json({ success: true, status: req.body.status });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/calls/:id/media-state', authMiddleware, async (req, res) => {
  try {
    const updates = {};
    if (req.body.callerVideoOff !== undefined) updates.callerVideoOff = Boolean(req.body.callerVideoOff);
    if (req.body.calleeVideoOff !== undefined) updates.calleeVideoOff = Boolean(req.body.calleeVideoOff);
    await fb.update(`calls/${req.params.id}`, updates);
    res.json({ success: true, mediaState: updates });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/calls/:id/join', authMiddleware, async (req, res) => {
  try {
    await fb.update(`calls/${req.params.id}/joined`, { [req.sanitizedUser]: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/calls/:id/leave', authMiddleware, async (req, res) => {
  try {
    await fb.remove(`calls/${req.params.id}/joined/${req.sanitizedUser}`);
    const joined = (await fb.get(`calls/${req.params.id}/joined`)) || {};
    if (Object.keys(joined).length === 0) {
      await fb.update(`calls/${req.params.id}`, {
        status: "ended",
        ended_at: new Date().toISOString()
      });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.post('/api/calls/:id/signal', authMiddleware, async (req, res) => {
  try {
    const { type, sdp, candidate, remoteUser } = req.body;
    if (remoteUser) {
      const remoteSan = sanitizeKey(remoteUser);
      const basePath = `call_signals/${req.params.id}/peers/${req.sanitizedUser}_to_${remoteSan}`;
      if (type === "offer") await fb.set(`${basePath}/offer`, { sdp, type });
      else if (type === "answer") await fb.set(`${basePath}/answer`, { sdp, type });
      else if (type === "candidate" && candidate) await fb.push(`${basePath}/candidates`, candidate);
    } else {
      if (type === "offer") await fb.set(`call_signals/${req.params.id}/offer`, { sdp, type });
      else if (type === "answer") await fb.set(`call_signals/${req.params.id}/answer`, { sdp, type });
      else if (type === "offerCandidate" && candidate) await fb.push(`call_signals/${req.params.id}/offerCandidates`, candidate);
      else if (type === "answerCandidate" && candidate) await fb.push(`call_signals/${req.params.id}/answerCandidates`, candidate);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

app.get('/api/calls/:id/signals', authMiddleware, async (req, res) => {
  try {
    const remoteUser = req.query.remoteUser;
    if (remoteUser) {
      const remoteSan = sanitizeKey(remoteUser);
      const signals = (await fb.get(`call_signals/${req.params.id}/peers/${remoteSan}_to_${req.sanitizedUser}`)) || {};
      res.json({ success: true, signals });
    } else {
      const signals = (await fb.get(`call_signals/${req.params.id}`)) || {};
      res.json({ success: true, signals });
    }
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Bulk Sync ----------
app.get('/api/sync', authMiddleware, async (req, res) => {
  try {
    const [users, groups, servers, announcements, calls] = await Promise.all([
      fb.get("users").catch(() => ({})),
      fb.get("groups").catch(() => ({})),
      fb.get("servers").catch(() => ({})),
      fb.get("announcements").catch(() => ({})),
      fb.get("calls").catch(() => ({}))
    ]);

    const safeProfiles = {};
    for (const [k, u] of Object.entries(users || {})) {
      if (u && u.username) safeProfiles[u.username.toLowerCase()] = cleanUserProfile(u);
    }

    const myGroups = {};
    for (const [gId, g] of Object.entries(groups || {})) {
      if (g && ((g.members || []).some(m => m && m.toLowerCase() === req.username.toLowerCase()) || isDev(req.username))) {
        myGroups[gId] = g;
      }
    }

    const myServers = {};
    for (const [sId, s] of Object.entries(servers || {})) {
      if (s && (getUserServerRole(s, req.username) || isDev(req.username) || s.forced)) {
        myServers[sId] = s;
      }
    }

    const myCalls = {};
    const myLow = req.username.toLowerCase();
    for (const [cId, c] of Object.entries(calls || {})) {
      if (c && c.status !== "ended") {
        if (
          c.caller?.toLowerCase() === myLow ||
          c.callee?.toLowerCase() === myLow ||
          (Array.isArray(c.participants) && c.participants.some(p => p.toLowerCase() === myLow))
        ) {
          myCalls[cId] = c;
        }
      }
    }

    res.json({
      success: true,
      currentUser: safeProfiles[req.username.toLowerCase()],
      users: safeProfiles,
      groups: myGroups,
      servers: myServers,
      announcements: Object.entries(announcements || {}).map(([id, val]) => ({ id, ...val })),
      calls: myCalls
    });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ---------- Start server (Render) ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Accordian Backend running on port ${PORT}`);
});

module.exports = app;
