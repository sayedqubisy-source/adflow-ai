import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

const dbPath = process.env.DB_PATH || '/app/data/adflow.sqlite';
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL DEFAULT 'starter',
    credits INTEGER NOT NULL DEFAULT 100,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    password_hash TEXT,
    updated_at TEXT
  );
  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    key TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS usage (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    endpoint TEXT NOT NULL,
    tool TEXT,
    units INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL DEFAULT 'content',
    title TEXT NOT NULL,
    input TEXT,
    output TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

function columnExists(table, column) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
}
if (!columnExists('users', 'password_hash')) db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT');
if (!columnExists('users', 'updated_at')) db.exec('ALTER TABLE users ADD COLUMN updated_at TEXT');
if (!columnExists('usage', 'tool')) db.exec('ALTER TABLE usage ADD COLUMN tool TEXT');

const plans = {
  starter: { name: 'Starter', credits: 100, price_usd: 19 },
  growth: { name: 'Growth', credits: 500, price_usd: 49 },
  scale: { name: 'Scale', credits: 2000, price_usd: 149 }
};

const makeKey = () => `af_${crypto.randomBytes(24).toString('hex')}`;
const makeToken = () => crypto.randomBytes(32).toString('hex');
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => e ? reject(e) : resolve(k)));
  return `scrypt:${salt.toString('hex')}:${key.toString('hex')}`;
}
async function verifyPassword(password, stored) {
  if (!stored?.startsWith('scrypt:')) return false;
  const [, saltHex, keyHex] = stored.split(':');
  if (!saltHex || !keyHex) return false;
  const original = Buffer.from(keyHex, 'hex');
  const key = await new Promise((resolve, reject) => crypto.scrypt(password, Buffer.from(saltHex, 'hex'), original.length, { N: 16384, r: 8, p: 1 }, (e, k) => e ? reject(e) : resolve(k)));
  return crypto.timingSafeEqual(original, key);
}

function parseCookies(req) {
  const cookies = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i !== -1) cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return cookies;
}
function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `adflow_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${secure}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'adflow_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}
function getUserById(id) { return db.prepare('SELECT * FROM users WHERE id = ?').get(id); }
function publicUser(user) { return { id: user.id, email: user.email, plan: user.plan, credits: user.credits, created_at: user.created_at }; }
function getUserFromApiKey(req) {
  const key = req.get('x-api-key');
  if (!key) return null;
  return db.prepare('SELECT u.* FROM users u JOIN api_keys a ON a.user_id = u.id WHERE a.key = ?').get(key) || null;
}
function getUserFromSession(req) {
  const token = parseCookies(req).adflow_session;
  if (!token) return null;
  const session = db.prepare("SELECT * FROM sessions WHERE token_hash = ? AND expires_at > datetime('now')").get(hashToken(token));
  return session ? getUserById(session.user_id) : null;
}
function auth(req, res, next) {
  const user = getUserFromSession(req) || getUserFromApiKey(req);
  if (!user) return res.status(401).json({ error: 'authentication_required' });
  req.user = user;
  next();
}
function spendCredit(userId, endpoint, tool) {
  const user = getUserById(userId);
  if (!user || user.credits < 1) return false;
  db.transaction(() => {
    db.prepare("UPDATE users SET credits = credits - 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(userId);
    db.prepare("INSERT INTO usage (user_id, endpoint, tool, units) VALUES (?, ?, ?, 1)").run(userId, endpoint, tool);
  })();
  return true;
}

app.use(express.static('public'));
app.get('/api/health', (req, res) => res.json({ ok: true, service: 'SQ AI', version: '3.0.0' }));
app.get('/api/plans', (req, res) => res.json(plans));

app.post('/api/auth/signup', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'valid_email_required' });
    if (password.length < 8) return res.status(400).json({ error: 'password_min_8_characters' });
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'email_already_registered' });
    const hash = await hashPassword(password);
    const result = db.prepare("INSERT INTO users (email, password_hash, plan, credits, updated_at) VALUES (?, ?, 'starter', ?, CURRENT_TIMESTAMP)").run(email, hash, plans.starter.credits);
    const user = getUserById(result.lastInsertRowid);
    const token = makeToken();
    db.prepare("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+30 days'))").run(user.id, hashToken(token));
    setSessionCookie(res, token);
    res.status(201).json({ user: publicUser(user) });
  } catch (e) { console.error('signup_error', e); res.status(500).json({ error: 'signup_failed' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'invalid_email_or_password' });
    if (!user.password_hash) return res.status(409).json({ error: 'legacy_account_requires_password_setup' });
    if (!(await verifyPassword(password, user.password_hash))) return res.status(401).json({ error: 'invalid_email_or_password' });
    const token = makeToken();
    db.prepare("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+30 days'))").run(user.id, hashToken(token));
    setSessionCookie(res, token);
    res.json({ user: publicUser(user) });
  } catch (e) { console.error('login_error', e); res.status(500).json({ error: 'login_failed' }); }
});

app.post('/api/auth/logout', (req, res) => {
  const token = parseCookies(req).adflow_session;
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
  clearSessionCookie(res);
  res.json({ ok: true });
});
app.post('/api/auth/set-password', auth, async (req, res) => {
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).json({ error: 'password_min_8_characters' });
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(await hashPassword(password), req.user.id);
  res.json({ ok: true, message: 'password_created' });
});
app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(getUserById(req.user.id)) }));

app.post('/api/signup', (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'valid_email_required' });
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) { const r = db.prepare('INSERT INTO users(email) VALUES(?)').run(email); user = getUserById(r.lastInsertRowid); }
    let key = db.prepare('SELECT key FROM api_keys WHERE user_id = ?').get(user.id);
    if (!key) { key = { key: makeKey() }; db.prepare('INSERT INTO api_keys(user_id, key) VALUES(?, ?)').run(user.id, key.key); }
    res.status(201).json({ user: publicUser(user), api_key: key.key });
  } catch (e) { console.error('legacy_signup_error', e); res.status(500).json({ error: 'signup_failed' }); }
});

app.get('/api/usage', auth, (req, res) => {
  const total = db.prepare('SELECT COALESCE(SUM(units),0) total FROM usage WHERE user_id = ?').get(req.user.id);
  res.json({ credits: req.user.credits, total_units: total.total });
});

const TOOL_REGISTRY = {
  video: ['video_script','ad_video','product_video','shorts','long_to_shorts','hooks','voiceover','subtitles'],
  image: ['image_prompt','product_image','ad_creative','thumbnail','background','variations'],
  content: ['writer','ad_copy','content_hooks','captions','script','product_description','cta','rewrite','summarize','translate','content_calendar','persona','audience_analysis'],
  ads: ['campaign_generator','audience','strategy','ad_hooks','ad_copy_ads','creative_concepts','video_script_ads','campaign_cta','campaign_plan','competitor_analysis','budget_roas']
};
const TOOL_META = {
  video_script: ['video','AI Video Script'], ad_video: ['video','Ad Video'], product_video: ['video','Product Video'], shorts: ['video','Reels / Shorts'], long_to_shorts: ['video','Long Video → Shorts'], hooks: ['video','Video Hooks'], voiceover: ['video','Voice-over'], subtitles: ['video','Subtitles'],
  image_prompt: ['image','Text → Image'], product_image: ['image','Product Image'], ad_creative: ['image','Ad Creative'], thumbnail: ['image','Thumbnail'], background: ['image','Background'], variations: ['image','Creative Variations'],
  writer: ['content','AI Writer'], ad_copy: ['content','Ad Copy'], content_hooks: ['content','Hooks'], captions: ['content','Captions'], script: ['content','Scripts'], product_description: ['content','Product Description'], cta: ['content','CTA'], rewrite: ['content','Rewrite'], summarize: ['content','Summarize'], translate: ['content','Translate'], content_calendar: ['content','Content Calendar'], persona: ['content','Customer Persona'], audience_analysis: ['content','Audience Analysis'],
  campaign_generator: ['ads','Campaign Generator'], audience: ['ads','Audience'], strategy: ['ads','Strategy'], ad_hooks: ['ads','Ad Hooks'], ad_copy_ads: ['ads','Ad Copy'], creative_concepts: ['ads','Creative Concepts'], video_script_ads: ['ads','Video Script'], campaign_cta: ['ads','CTA'], campaign_plan: ['ads','Campaign Plan'], competitor_analysis: ['ads','Competitor Analysis'], budget_roas: ['ads','Budget / ROAS']
};
const TOOL_ALIASES = { 'ai-writer':'writer', 'ad-copy':'ad_copy', 'scripts':'script', 'campaign':'campaign_generator', 'product-description':'product_description' };
function allTools() { return Object.entries(TOOL_REGISTRY).flatMap(([category, ids]) => ids.map(id => ({ id, category, name: TOOL_META[id]?.[1] || id }))); }
function normalizeToolId(raw) { const value = String(raw || '').trim(); return TOOL_ALIASES[value] || value; }
function getTool(raw) { const id = normalizeToolId(raw); return allTools().find(t => t.id === id) || null; }
function providerStatus(type) {
  const envName = { text:'AI_TEXT_PROVIDER', image:'AI_IMAGE_PROVIDER', video:'AI_VIDEO_PROVIDER', audio:'AI_AUDIO_PROVIDER' }[type] || 'AI_TEXT_PROVIDER';
  return { configured:Boolean(process.env[envName]), provider:process.env[envName] || null, envName };
}
async function aiEngine({ tool, type }) {
  const kind = ['video','image','audio','text'].includes(type) ? type : (['image','video'].includes(tool.category) ? tool.category : 'text');
  const status = providerStatus(kind);
  if (!status.configured) return { ok:false, error:'provider_not_configured', message:`No ${kind} AI provider is configured yet. The tool is registered and ready for a provider adapter.`, tool:tool.id, category:tool.category, engine:'SQ AI Engine', provider:null };
  return { ok:false, error:'provider_adapter_not_implemented', message:`Provider ${status.provider} is configured but its adapter is not implemented yet.`, tool:tool.id, category:tool.category, engine:'SQ AI Engine', provider:status.provider };
}
app.get('/api/tools', (req,res) => res.json({ tools:allTools(), registry:TOOL_REGISTRY }));
app.post('/api/tools/generate', auth, async (req,res) => {
  const tool = getTool(req.body.tool);
  const input = String(req.body.input ?? req.body.prompt ?? '').trim().slice(0,12000);
  const requestedType = String(req.body.type || '').trim().toLowerCase();
  if (!tool) return res.status(400).json({ error:'unknown_tool', message:'The requested tool is not registered.' });
  if (!input) return res.status(400).json({ error:'input_required' });
  if (req.user.credits < 1) return res.status(402).json({ error:'credits_exhausted' });
  const result = await aiEngine({ tool, type:requestedType || tool.category });
  if (!result.ok) return res.status(503).json(result);
  if (!spendCredit(req.user.id,'/api/tools/generate',tool.id)) return res.status(402).json({ error:'credits_exhausted' });
  res.json({ data:result.output, credits_remaining:getUserById(req.user.id).credits });
});

app.post('/api/generate', auth, (req,res) => {
  if (!spendCredit(req.user.id,'/api/generate','legacy-generate')) return res.status(402).json({ error:'credits_exhausted' });
  const product = String(req.body.product || 'product').slice(0,200);
  const data = { hook:`Stop scrolling — discover ${product} made for people who want more.`, angles:['Problem → solution','Benefit-led','Social proof'], cta:'Try it today', formats:['9:16','1:1','16:9'] };
  res.json({ data, credits_remaining:getUserById(req.user.id).credits });
});

app.get('/api/projects', auth, (req,res) => res.json({ projects:db.prepare('SELECT id,type,title,input,output,created_at,updated_at FROM projects WHERE user_id = ? ORDER BY updated_at DESC').all(req.user.id) }));
app.post('/api/projects', auth, (req,res) => {
  const type=String(req.body.type||'content').slice(0,50), title=String(req.body.title||'Untitled Project').slice(0,150);
  const input=req.body.input==null?'':JSON.stringify(req.body.input), output=req.body.output==null?'':JSON.stringify(req.body.output);
  const r=db.prepare('INSERT INTO projects (user_id,type,title,input,output) VALUES (?,?,?,?,?)').run(req.user.id,type,title,input,output);
  res.status(201).json({ project:db.prepare('SELECT * FROM projects WHERE id = ?').get(r.lastInsertRowid) });
});
app.get('/api/projects/:id', auth, (req,res) => { const project=db.prepare('SELECT * FROM projects WHERE id=? AND user_id=?').get(Number(req.params.id),req.user.id); if(!project)return res.status(404).json({error:'project_not_found'}); res.json({project}); });
app.delete('/api/projects/:id', auth, (req,res) => { const r=db.prepare('DELETE FROM projects WHERE id=? AND user_id=?').run(Number(req.params.id),req.user.id); if(!r.changes)return res.status(404).json({error:'project_not_found'}); res.json({ok:true}); });

app.post('/api/campaigns/generate', auth, (req,res) => {
  if (req.user.credits < 1) return res.status(402).json({error:'credits_exhausted'});
  const product=String(req.body.product||'Your Product').slice(0,200), audience=String(req.body.audience||'General Audience').slice(0,200), platform=String(req.body.platform||'Facebook').slice(0,50);
  const campaign={product,audience,platform,objective:'Conversions',strategy:'Problem → Solution → Proof → CTA',hooks:[`Stop scrolling: ${product}`,`What if ${product} could solve your biggest problem?`,`People are choosing ${product} for a reason.`],ad_copy:`Discover ${product} designed for ${audience}.`,cta:'Get started today',formats:['9:16','1:1','16:9']};
  if(!spendCredit(req.user.id,'/api/campaigns/generate','campaign'))return res.status(402).json({error:'credits_exhausted'});
  db.prepare('INSERT INTO campaigns (user_id,name,data) VALUES (?,?,?)').run(req.user.id,`${product} Campaign`,JSON.stringify(campaign));
  res.json({campaign,credits_remaining:getUserById(req.user.id).credits});
});

app.post('/api/billing/checkout', auth, (req,res) => res.status(501).json({error:'payment_provider_not_configured',message:'Paddle integration is not connected yet.'}));
app.use((err,req,res,next) => { console.error('internal_error',err); res.status(500).json({error:'internal_error'}); });
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`SQ AI listening on port ${port}`));
