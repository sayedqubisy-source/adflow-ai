import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const app = express();

app.disable('x-powered-by');

const ROOT = process.cwd();
const PORT = Number(process.env.PORT || 3000);

// =========================
// Database
// =========================

const dbPath = process.env.DB_PATH || '/app/data/adflow.sqlite';

fs.mkdirSync(path.dirname(path.resolve(dbPath)), {
  recursive: true
});

const db = new Database(dbPath);

db.pragma('journal_mode=WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL DEFAULT 'starter',
  credits INTEGER NOT NULL DEFAULT 100,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  key TEXT UNIQUE NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS usage(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  endpoint TEXT NOT NULL,
  units INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

// =========================
// Plans
// =========================

const plans = {
  starter: {
    credits: 100,
    price_usd: 19,
    price_id: 'pri_01m228xvs639e2q6bq8heh0mgq'
  },

  growth: {
    credits: 500,
    price_usd: 49,
    price_id: 'pri_01m229502rmkzrj65zn60ee3ns'
  },

  scale: {
    credits: 2000,
    price_usd: 149,
    price_id: 'pri_01m2296hjwyqhaxftffp7fkxg4'
  }
};

// =========================
// Helpers
// =========================

const makeKey = () =>
  `af_${crypto.randomBytes(24).toString('hex')}`;

const sendFileIfExists = (res, filename) => {
  const filePath = path.join(ROOT, filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Not Found</title>
      </head>
      <body>
        <h1>404 - File Not Found</h1>
        <p>${filename} was not found on the server.</p>
      </body>
      </html>
    `);
  }

  return res.sendFile(filePath);
};

// =========================
// Middleware
// =========================

app.use(express.json({
  limit: '64kb'
}));

// =========================
// Website
// =========================

// Homepage
app.get('/', (req, res) => {
  sendFileIfExists(res, 'index.html');
});

// Terms of Service
app.get('/terms.html', (req, res) => {
  sendFileIfExists(res, 'terms.html');
});

// Privacy Notice
app.get('/privacy.html', (req, res) => {
  sendFileIfExists(res, 'privacy.html');
});

// Refund Policy
app.get('/refund.html', (req, res) => {
  sendFileIfExists(res, 'refund.html');
});

// Also support clean URLs
app.get('/terms', (req, res) => {
  sendFileIfExists(res, 'terms.html');
});

app.get('/privacy', (req, res) => {
  sendFileIfExists(res, 'privacy.html');
});

app.get('/refund', (req, res) => {
  sendFileIfExists(res, 'refund.html');
});

// =========================
// Paddle Client Token
// =========================

app.get('/api/config', (req, res) => {
  const token = process.env.PADDLE_CLIENT_TOKEN;

  if (!token) {
    return res.status(500).json({
      error: 'paddle_client_token_not_configured'
    });
  }

  res.json({
    paddleClientToken: token
  });
});

// =========================
// Health Check
// =========================

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'SQ AI',
    version: '1.0.0'
  });
});

// =========================
// Public Plans
// =========================

app.get('/api/plans', (req, res) => {
  res.json(plans);
});

// =========================
// Authentication
// =========================

const auth = (req, res, next) => {
  const key = req.get('x-api-key');

  const user = key && db.prepare(`
    SELECT u.*
    FROM users u
    JOIN api_keys a ON a.user_id = u.id
    WHERE a.key = ?
  `).get(key);

  if (!user) {
    return res.status(401).json({
      error: 'invalid_api_key'
    });
  }

  req.user = user;
  next();
};

// =========================
// Signup
// =========================

app.post('/api/signup', (req, res) => {
  const email = String(req.body.email || '')
    .trim()
    .toLowerCase();

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({
      error: 'valid_email_required'
    });
  }

  let user = db.prepare(
    'SELECT * FROM users WHERE email = ?'
  ).get(email);

  if (!user) {
    const result = db.prepare(
      'INSERT INTO users(email) VALUES(?)'
    ).run(email);

    user = db.prepare(
      'SELECT * FROM users WHERE id = ?'
    ).get(result.lastInsertRowid);
  }

  let apiKey = db.prepare(
    'SELECT key FROM api_keys WHERE user_id = ?'
  ).get(user.id);

  if (!apiKey) {
    apiKey = {
      key: makeKey()
    };

    db.prepare(
      'INSERT INTO api_keys(user_id, key) VALUES(?, ?)'
    ).run(user.id, apiKey.key);
  }

  res.status(201).json({
    user: {
      id: user.id,
      email: user.email,
      plan: user.plan,
      credits: user.credits
    },
    api_key: apiKey.key
  });
});

// =========================
// Current User
// =========================

app.get('/api/me', auth, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    plan: req.user.plan,
    credits: req.user.credits
  });
});

// =========================
// Generate
// =========================

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
    db.prepare(
      'UPDATE users SET credits = credits - 1 WHERE id = ?'
    ).run(req.user.id);

    db.prepare(
      'INSERT INTO usage(user_id, endpoint, units) VALUES(?, ?, 1)'
    ).run(
      req.user.id,
      'generate'
    );
  })();

  res.json({
    data,
    credits_remaining: req.user.credits - 1
  });
});

// =========================
// Usage
// =========================

app.get('/api/usage', auth, (req, res) => {
  const total = db.prepare(`
    SELECT COALESCE(SUM(units), 0) AS n
    FROM usage
    WHERE user_id = ?
  `).get(req.user.id).n;

  res.json({
    credits: req.user.credits,
    total_units: total
  });
});

// =========================
// Billing Checkout
// =========================

app.post('/api/billing/checkout', auth, (req, res) => {
  const plan = String(
    req.body.plan || ''
  ).toLowerCase();

  if (!plans[plan]) {
    return res.status(400).json({
      error: 'invalid_plan'
    });
  }

  res.json({
    ok: true,
    plan,
    price_id: plans[plan].price_id,
    message: 'Use Paddle Checkout on the client to complete payment.'
  });
});

// =========================
// Welcome
// =========================

app.get('/welcome', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  >
  <title>Welcome - SQ AI</title>

  <style>
    body {
      font-family: Arial, sans-serif;
      text-align: center;
      padding: 80px 20px;
      background: #f7f7f7;
      color: #111;
    }

    h1 {
      font-size: 40px;
    }

    p {
      font-size: 20px;
      color: #555;
    }

    a {
      display: inline-block;
      margin-top: 20px;
      color: #111;
    }
  </style>
</head>

<body>

  <h1>Welcome to SQ AI 🎉</h1>

  <p>
    Your checkout was completed successfully.
  </p>

  <a href="/">
    Back to SQ AI
  </a>

</body>
</html>
  `);
});

// =========================
// 404
// =========================

app.use((req, res) => {
  res.status(404).send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>404 - SQ AI</title>
</head>

<body style="
  font-family: Arial, sans-serif;
  text-align: center;
  padding: 80px 20px;
">

  <h1>404</h1>

  <p>
    Page not found.
  </p>

  <a href="/">
    Go to SQ AI
  </a>

</body>
</html>
  `);
});

// =========================
// Error Handler
// =========================

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: 'internal_error'
  });
});

// =========================
// Start Server
// =========================

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `SQ AI listening on port ${PORT}`
  );
});
