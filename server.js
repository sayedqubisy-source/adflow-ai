import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

/* =========================================================
   DATABASE
========================================================= */

const dbPath = process.env.DB_PATH || '/app/data/adflow.sqlite';

fs.mkdirSync(path.dirname(path.resolve(dbPath)), {
  recursive: true
});

const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

/* =========================================================
   BASE TABLES
========================================================= */

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL DEFAULT 'starter',
    credits INTEGER NOT NULL DEFAULT 100,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
    units INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

/* =========================================================
   SAFE MIGRATIONS
   These upgrades preserve the existing database.
========================================================= */

function columnExists(table, column) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  return columns.some((c) => c.name === column);
}

if (!columnExists('users', 'password_hash')) {
  db.exec(`ALTER TABLE users ADD COLUMN password_hash TEXT`);
}

if (!columnExists('users', 'updated_at')) {
  db.exec(`ALTER TABLE users ADD COLUMN updated_at TEXT`);
}

if (!columnExists('usage', 'tool')) {
  db.exec(`ALTER TABLE usage ADD COLUMN tool TEXT`);
}

/* =========================================================
   NEW TABLES
========================================================= */

db.exec(`
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

/* =========================================================
   PLANS
========================================================= */

const plans = {
  starter: {
    name: 'Starter',
    credits: 100,
    price_usd: 19
  },

  growth: {
    name: 'Growth',
    credits: 500,
    price_usd: 49
  },

  scale: {
    name: 'Scale',
    credits: 2000,
    price_usd: 149
  }
};

/* =========================================================
   SECURITY HELPERS
========================================================= */

const makeKey = () =>
  `af_${crypto.randomBytes(24).toString('hex')}`;

const makeToken = () =>
  crypto.randomBytes(32).toString('hex');

const hashToken = (token) =>
  crypto.createHash('sha256').update(token).digest('hex');

const hashPassword = async (password) => {
  const salt = crypto.randomBytes(16);

  const derivedKey = await new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      64,
      {
        N: 16384,
        r: 8,
        p: 1
      },
      (err, key) => {
        if (err) reject(err);
        else resolve(key);
      }
    );
  });

  return `scrypt:${salt.toString('hex')}:${derivedKey.toString('hex')}`;
};

const verifyPassword = async (password, stored) => {
  if (!stored || !stored.startsWith('scrypt:')) {
    return false;
  }

  const [, saltHex, keyHex] = stored.split(':');

  if (!saltHex || !keyHex) {
    return false;
  }

  const salt = Buffer.from(saltHex, 'hex');
  const originalKey = Buffer.from(keyHex, 'hex');

  const derivedKey = await new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      originalKey.length,
      {
        N: 16384,
        r: 8,
        p: 1
      },
      (err, key) => {
        if (err) reject(err);
        else resolve(key);
      }
    );
  });

  return crypto.timingSafeEqual(originalKey, derivedKey);
};

/* =========================================================
   COOKIE HELPERS
========================================================= */

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};

  header.split(';').forEach((part) => {
    const index = part.indexOf('=');

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  });

  return cookies;
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production'
    ? '; Secure'
    : '';

  res.setHeader(
    'Set-Cookie',
    `adflow_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${secure}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    'adflow_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
  );
}

/* =========================================================
   USER HELPERS
========================================================= */

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    plan: user.plan,
    credits: user.credits,
    created_at: user.created_at
  };
}

function getUserById(id) {
  return db
    .prepare('SELECT * FROM users WHERE id = ?')
    .get(id);
}

/* =========================================================
   AUTHENTICATION
========================================================= */

function getUserFromApiKey(req) {
  const key = req.get('x-api-key');

  if (!key) {
    return null;
  }

  return db
    .prepare(`
      SELECT u.*
      FROM users u
      JOIN api_keys a ON a.user_id = u.id
      WHERE a.key = ?
    `)
    .get(key) || null;
}

function getUserFromSession(req) {
  const cookies = parseCookies(req);
  const token = cookies.adflow_session;

  if (!token) {
    return null;
  }

  const tokenHash = hashToken(token);

  const session = db
    .prepare(`
      SELECT *
      FROM sessions
      WHERE token_hash = ?
        AND expires_at > datetime('now')
    `)
    .get(tokenHash);

  if (!session) {
    return null;
  }

  return getUserById(session.user_id);
}

/*
  New authentication:
  1. Cookie session
  2. Old API key fallback

  This means existing integrations do not break.
*/

function auth(req, res, next) {
  const user =
    getUserFromSession(req) ||
    getUserFromApiKey(req);

  if (!user) {
    return res.status(401).json({
      error: 'authentication_required'
    });
  }

  req.user = user;
  next();
}

/* =========================================================
   STATIC WEBSITE
========================================================= */

app.use(express.static('public'));

/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'AdFlow AI',
    version: '2.0.0'
  });
});

/* =========================================================
   PLANS
========================================================= */

app.get('/api/plans', (req, res) => {
  res.json(plans);
});

/* =========================================================
   NEW SIGNUP
========================================================= */

app.post('/api/auth/signup', async (req, res) => {
  try {
    const email = String(req.body.email || '')
      .trim()
      .toLowerCase();

    const password = String(req.body.password || '');

    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({
        error: 'valid_email_required'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'password_min_8_characters'
      });
    }

    const existing = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(email);

    if (existing) {
      return res.status(409).json({
        error: 'email_already_registered'
      });
    }

    const passwordHash = await hashPassword(password);

    const result = db
      .prepare(`
        INSERT INTO users
        (email, password_hash, plan, credits, updated_at)
        VALUES (?, ?, 'starter', ?, CURRENT_TIMESTAMP)
      `)
      .run(
        email,
        passwordHash,
        plans.starter.credits
      );

    const user = getUserById(result.lastInsertRowid);

    const token = makeToken();
    const tokenHash = hashToken(token);

    db.prepare(`
      INSERT INTO sessions
      (user_id, token_hash, expires_at)
      VALUES (?, ?, datetime('now', '+30 days'))
    `).run(user.id, tokenHash);

    setSessionCookie(res, token);

    res.status(201).json({
      user: publicUser(user)
    });
  } catch (error) {
    console.error('signup_error', error);

    res.status(500).json({
      error: 'signup_failed'
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '')
      .trim()
      .toLowerCase();

    const password = String(req.body.password || '');

    if (!email || !password) {
      return res.status(400).json({
        error: 'email_and_password_required'
      });
    }

    const user = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(email);

    if (!user) {
      return res.status(401).json({
        error: 'invalid_email_or_password'
      });
    }

    /*
      Old users created by the original API do not have
      password_hash yet. They can use the legacy API key
      migration endpoint below to create a password.
    */

    if (!user.password_hash) {
      return res.status(409).json({
        error: 'legacy_account_requires_password_setup'
      });
    }

    const valid = await verifyPassword(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: 'invalid_email_or_password'
      });
    }

    const token = makeToken();
    const tokenHash = hashToken(token);

    db.prepare(`
      INSERT INTO sessions
      (user_id, token_hash, expires_at)
      VALUES (?, ?, datetime('now', '+30 days'))
    `).run(user.id, tokenHash);

    setSessionCookie(res, token);

    res.json({
      user: publicUser(user)
    });
  } catch (error) {
    console.error('login_error', error);

    res.status(500).json({
      error: 'login_failed'
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post('/api/auth/logout', (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies.adflow_session;

  if (token) {
    db.prepare(
      'DELETE FROM sessions WHERE token_hash = ?'
    ).run(hashToken(token));
  }

  clearSessionCookie(res);

  res.json({
    ok: true
  });
});

/* =========================================================
   LEGACY ACCOUNT PASSWORD SETUP
========================================================= */

app.post('/api/auth/set-password', auth, async (req, res) => {
  try {
    const password = String(req.body.password || '');

    if (password.length < 8) {
      return res.status(400).json({
        error: 'password_min_8_characters'
      });
    }

    const passwordHash = await hashPassword(password);

    db.prepare(`
      UPDATE users
      SET password_hash = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(passwordHash, req.user.id);

    res.json({
      ok: true,
      message: 'password_created'
    });
  } catch (error) {
    console.error('set_password_error', error);

    res.status(500).json({
      error: 'password_setup_failed'
    });
  }
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get('/api/me', auth, (req, res) => {
  const user = getUserById(req.user.id);

  res.json({
    user: publicUser(user)
  });
});

/* =========================================================
   LEGACY SIGNUP API
   Kept so existing clients don't break.
========================================================= */

app.post('/api/signup', (req, res) => {
  try {
    const email = String(req.body.email || '')
      .trim()
      .toLowerCase();

    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({
        error: 'valid_email_required'
      });
    }

    let user = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(email);

    if (!user) {
      const result = db
        .prepare('INSERT INTO users(email) VALUES(?)')
        .run(email);

      user = getUserById(result.lastInsertRowid);
    }

    let apiKey = db
      .prepare(`
        SELECT key
        FROM api_keys
        WHERE user_id = ?
      `)
      .get(user.id);

    if (!apiKey) {
      apiKey = {
        key: makeKey()
      };

      db.prepare(`
        INSERT INTO api_keys(user_id, key)
        VALUES(?, ?)
      `).run(user.id, apiKey.key);
    }

    res.status(201).json({
      user: publicUser(user),
      api_key: apiKey.key
    });
  } catch (error) {
    console.error('legacy_signup_error', error);

    res.status(500).json({
      error: 'signup_failed'
    });
  }
});

/* =========================================================
   USAGE
========================================================= */

app.get('/api/usage', auth, (req, res) => {
  const total = db
    .prepare(`
      SELECT COALESCE(SUM(units), 0) AS total
      FROM usage
      WHERE user_id = ?
    `)
    .get(req.user.id);

  res.json({
    credits: req.user.credits,
    total_units: total.total
  });
});

/* =========================================================
   TOOL CATALOG
========================================================= */

const tools = [
  {
    id: 'ai-writer',
    category: 'content',
    name: 'AI Writer',
    description: 'Create high-quality marketing content.'
  },
  {
    id: 'ad-copy',
    category: 'ads',
    name: 'Ad Copy',
    description: 'Generate advertising copy and CTAs.'
  },
  {
    id: 'hooks',
    category: 'content',
    name: 'Hooks',
    description: 'Generate scroll-stopping hooks.'
  },
  {
    id: 'scripts',
    category: 'video',
    name: 'Video Scripts',
    description: 'Create short-form video scripts.'
  },
  {
    id: 'campaign',
    category: 'ads',
    name: 'Campaign Generator',
    description: 'Build a complete advertising campaign.'
  },
  {
    id: 'product-description',
    category: 'content',
    name: 'Product Description',
    description: 'Write persuasive product descriptions.'
  }
];

app.get('/api/tools', (req, res) => {
  res.json({
    tools
  });
});

/* =========================================================
   GENERIC TOOL GENERATOR
========================================================= */

app.post('/api/tools/generate', auth, (req, res) => {
  if (req.user.credits < 1) {
    return res.status(402).json({
      error: 'credits_exhausted'
    });
  }

  const tool = String(req.body.tool || '').trim();
  const input = String(req.body.input || '').trim();

  const exists = tools.find((item) => item.id === tool);

  if (!exists) {
    return res.status(400).json({
      error: 'unknown_tool'
    });
  }

  if (!input) {
    return res.status(400).json({
      error: 'input_required'
    });
  }

  const output = {
    tool,
    result: `AdFlow AI generated a result for: ${input}`,
    suggestions: [
      'Problem → Solution',
      'Benefit-led',
      'Social proof',
      'Urgency'
    ]
  };

  db.transaction(() => {
    db.prepare(`
      UPDATE users
      SET credits = credits - 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(req.user.id);

    db.prepare(`
      INSERT INTO usage
      (user_id, endpoint, tool, units)
      VALUES (?, ?, ?, 1)
    `).run(
      req.user.id,
      '/api/tools/generate',
      tool
    );
  })();

  const updatedUser = getUserById(req.user.id);

  res.json({
    data: output,
    credits_remaining: updatedUser.credits
  });
});

/* =========================================================
   LEGACY GENERATE API
========================================================= */

app.post('/api/generate', auth, (req, res) => {
  if (req.user.credits < 1) {
    return res.status(402).json({
      error: 'credits_exhausted'
    });
  }

  const product = String(
    req.body.product || 'product'
  ).slice(0, 200);

  const data = {
    hook: `Stop scrolling — discover ${product} made for people who want more.`,
    angles: [
      'Problem → solution',
      'Benefit-led',
      'Social proof'
    ],
    cta: 'Try it today',
    formats: [
      '9:16',
      '1:1',
      '16:9'
    ]
  };

  db.transaction(() => {
    db.prepare(`
      UPDATE users
      SET credits = credits - 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(req.user.id);

    db.prepare(`
      INSERT INTO usage
      (user_id, endpoint, tool, units)
      VALUES (?, ?, ?, 1)
    `).run(
      req.user.id,
      '/api/generate',
      'legacy-generate'
    );
  })();

  const updatedUser = getUserById(req.user.id);

  res.json({
    data,
    credits_remaining: updatedUser.credits
  });
});

/* =========================================================
   PROJECTS
========================================================= */

app.get('/api/projects', auth, (req, res) => {
  const projects = db
    .prepare(`
      SELECT
        id,
        type,
        title,
        input,
        output,
        created_at,
        updated_at
      FROM projects
      WHERE user_id = ?
      ORDER BY updated_at DESC
    `)
    .all(req.user.id);

  res.json({
    projects
  });
});

app.post('/api/projects', auth, (req, res) => {
  const type = String(req.body.type || 'content')
    .slice(0, 50);

  const title = String(req.body.title || 'Untitled Project')
    .slice(0, 150);

  const input = req.body.input == null
    ? ''
    : JSON.stringify(req.body.input);

  const output = req.body.output == null
    ? ''
    : JSON.stringify(req.body.output);

  const result = db.prepare(`
    INSERT INTO projects
    (user_id, type, title, input, output)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    req.user.id,
    type,
    title,
    input,
    output
  );

  const project = db
    .prepare('SELECT * FROM projects WHERE id = ?')
    .get(result.lastInsertRowid);

  res.status(201).json({
    project
  });
});

app.get('/api/projects/:id', auth, (req, res) => {
  const project = db
    .prepare(`
      SELECT *
      FROM projects
      WHERE id = ?
        AND user_id = ?
    `)
    .get(
      Number(req.params.id),
      req.user.id
    );

  if (!project) {
    return res.status(404).json({
      error: 'project_not_found'
    });
  }

  res.json({
    project
  });
});

app.delete('/api/projects/:id', auth, (req, res) => {
  const result = db
    .prepare(`
      DELETE FROM projects
      WHERE id = ?
        AND user_id = ?
    `)
    .run(
      Number(req.params.id),
      req.user.id
    );

  if (!result.changes) {
    return res.status(404).json({
      error: 'project_not_found'
    });
  }

  res.json({
    ok: true
  });
});

/* =========================================================
   CAMPAIGN GENERATOR FOUNDATION
========================================================= */

app.post('/api/campaigns/generate', auth, (req, res) => {
  if (req.user.credits < 1) {
    return res.status(402).json({
      error: 'credits_exhausted'
    });
  }

  const product = String(
    req.body.product || 'Your Product'
  ).slice(0, 200);

  const audience = String(
    req.body.audience || 'General Audience'
  ).slice(0, 200);

  const platform = String(
    req.body.platform || 'Facebook'
  ).slice(0, 50);

  const campaign = {
    product,
    audience,
    platform,
    objective: 'Conversions',
    strategy: 'Problem → Solution → Proof → CTA',
    hooks: [
      `Stop scrolling: ${product}`,
      `What if ${product} could solve your biggest problem?`,
      `People are choosing ${product} for a reason.`
    ],
    ad_copy: `Discover ${product} designed for ${audience}.`,
    cta: 'Get started today',
    formats: [
      '9:16',
      '1:1',
      '16:9'
    ]
  };

  const name = `${product} Campaign`;

  db.transaction(() => {
    db.prepare(`
      UPDATE users
      SET credits = credits - 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(req.user.id);

    db.prepare(`
      INSERT INTO usage
      (user_id, endpoint, tool, units)
      VALUES (?, ?, ?, 1)
    `).run(
      req.user.id,
      '/api/campaigns/generate',
      'campaign'
    );

    db.prepare(`
      INSERT INTO campaigns
      (user_id, name, data)
      VALUES (?, ?, ?)
    `).run(
      req.user.id,
      name,
      JSON.stringify(campaign)
    );
  })();

  const updatedUser = getUserById(req.user.id);

  res.json({
    campaign,
    credits_remaining: updatedUser.credits
  });
});

/* =========================================================
   BILLING FOUNDATION
========================================================= */

app.post('/api/billing/checkout', auth, (req, res) => {
  res.status(501).json({
    error: 'payment_provider_not_configured',
    message:
      'Paddle integration will be connected after the product foundation is complete.'
  });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
  console.error('internal_error', err);

  res.status(500).json({
    error: 'internal_error'
  });
});

/* =========================================================
   SERVER
========================================================= */

const port = Number(process.env.PORT || 3000);

app.listen(port, () => {
  console.log(
    `AdFlow AI listening on port ${port}`
  );
});
