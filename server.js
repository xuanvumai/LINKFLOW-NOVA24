
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const dns = require("node:dns").promises;
const net = require("node:net");
const path = require("node:path");
const crypto = require("node:crypto");
const fs = require("node:fs");

const required = [
  "DATABASE_URL",
  "JWT_SECRET",
  "ADMIN_EMAIL",
  "ADMIN_PASSWORD"
];

for (const key of required) {
  if (!process.env[key]) {
    throw new Error("Missing environment variable: " + key);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const app = express();

app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "https://img.vietqr.io", "data:"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"]
    }
  }
}));

app.use(express.json({ limit: "32kb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30
});

const resolveLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 10
});

async function init() {
  await pool.query(
    fs.readFileSync(
      path.join(__dirname, "schema.sql"),
      "utf8"
    )
  );

  const email = process.env.ADMIN_EMAIL.toLowerCase();

  const exists = await pool.query(
    "SELECT id FROM users WHERE email=$1",
    [email]
  );

  if (!exists.rowCount) {
    const hash = await bcrypt.hash(
      process.env.ADMIN_PASSWORD,
      12
    );

    await pool.query(
      "INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin')",
      [email, hash]
    );
  }
}

function sign(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      role: user.role
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function requireAuth(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer\s+/i, "");

    if (!token) {
      return res.status(401).json({
        error: "Vui lòng đăng nhập"
      });
    }

    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    const result = await pool.query(
      "SELECT id,email,role,balance FROM users WHERE id=$1",
      [payload.sub]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Tài khoản không tồn tại"
      });
    }

    req.user = result.rows[0];
    next();

  } catch {
    res.status(401).json({
      error: "Phiên đăng nhập không hợp lệ"
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      error: "Không có quyền quản trị"
    });
  }

  next();
}

// REGISTER

app.post("/api/auth/register", authLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim().toLowerCase();

    const password = String(req.body.password || "");

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 10 ||
      password.length > 100
    ) {
      return res.status(400).json({
        error: "Email hoặc mật khẩu không hợp lệ"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      "INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email,role,balance",
      [email, hash]
    );

    res.status(201).json({
      token: sign(result.rows[0]),
      user: result.rows[0]
    });

  } catch (error) {
    res.status(error.code === "23505" ? 409 : 500).json({
      error: "Không thể tạo tài khoản"
    });
  }
});

// LOGIN

app.post("/api/auth/login", authLimit, async (req, res) => {
  const email = String(req.body.email || "")
    .trim().toLowerCase();

  const result = await pool.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  if (
    !result.rowCount ||
    !(await bcrypt.compare(
      String(req.body.password || ""),
      result.rows[0].password_hash
    ))
  ) {
    return res.status(401).json({
      error: "Email hoặc mật khẩu không đúng"
    });
  }

  const user = result.rows[0];

  res.json({
    token: sign(user),
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      balance: user.balance
    }
  });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// CREATE TOPUP

app.post("/api/topups", requireAuth, async (req, res) => {
  const amount = Number(req.body.amount);

  const min = Number(process.env.MIN_TOPUP_VND || 10000);
  const max = Number(process.env.MAX_TOPUP_VND || 50000000);

  if (
    !Number.isSafeInteger(amount) ||
    amount < min ||
    amount > max
  ) {
    return res.status(400).json({
      error: "Số tiền nạp không hợp lệ"
    });
  }

  const {
    BANK_CODE,
    BANK_ACCOUNT,
    BANK_ACCOUNT_NAME
  } = process.env;

  if (
    !BANK_CODE ||
    !BANK_ACCOUNT ||
    !BANK_ACCOUNT_NAME ||
    BANK_ACCOUNT.includes("YOUR_")
  ) {
    return res.status(503).json({
      error: "Chưa cấu hình tài khoản ngân hàng"
    });
  }

  const reference =
    "NOVA" +
    Date.now().toString(36).toUpperCase() +
    crypto.randomBytes(3).toString("hex").toUpperCase();

  const minutes = Number(
    process.env.PAYMENT_EXPIRE_MINUTES || 5
  );

  const result = await pool.query(
    `INSERT INTO topups
    (user_id,reference,amount,expires_at)
    VALUES($1,$2,$3,NOW()+($4 || ' minutes')::interval)
    RETURNING id,reference,amount,status,expires_at`,
    [req.user.id, reference, amount, minutes]
  );

  const topup = result.rows[0];

  const qr =
    `https://img.vietqr.io/image/` +
    `${encodeURIComponent(BANK_CODE)}-` +
    `${encodeURIComponent(BANK_ACCOUNT)}-compact2.png` +
    `?amount=${amount}` +
    `&addInfo=${encodeURIComponent(reference)}` +
    `&accountName=${encodeURIComponent(BANK_ACCOUNT_NAME)}`;

  res.status(201).json({
    topup,
    qr,
    bank: BANK_CODE,
    account: BANK_ACCOUNT,
    accountName: BANK_ACCOUNT_NAME
  });
});

app.get("/api/topups", requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT id,reference,amount,status,expires_at,
    created_at,paid_at
    FROM topups
    WHERE user_id=$1
    ORDER BY id DESC LIMIT 30`,
    [req.user.id]
  );

  res.json({ topups: result.rows });
});

app.get("/api/ledger", requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT amount,description,created_at
    FROM wallet_ledger
    WHERE user_id=$1
    ORDER BY id DESC LIMIT 50`,
    [req.user.id]
  );

  res.json({ entries: result.rows });
});

// SEPAY WEBHOOK

app.post("/api/webhooks/sepay", async (req, res) => {
  const secret = process.env.SEPAY_API_KEY;

  if (!secret) {
    return res.status(503).json({
      error: "Webhook chưa cấu hình"
    });
  }

  const auth = req.headers.authorization || "";
  const supplied = auth.replace(/^Apikey\s+/i, "").trim();

  const a = Buffer.from(supplied);
  const b = Buffer.from(secret);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  const body = req.body || {};

  const type = String(
    body.transferType || body.transfer_type || ""
  ).toLowerCase();

  const amount = Number(
    body.transferAmount ?? body.amount
  );

  const content = String(
    body.content ||
    body.description ||
    body.transactionContent ||
    ""
  );

  const txId = String(
    body.id ?? body.transaction_id ?? ""
  );

  const match = content.match(/NOVA[A-Z0-9]+/i);

  if (
    !txId ||
    !match ||
    !Number.isSafeInteger(amount) ||
    amount <= 0 ||
    (type && !["in", "credit"].includes(type))
  ) {
    return res.status(400).json({
      error: "Giao dịch không hợp lệ"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM topups WHERE reference=$1 FOR UPDATE",
      [match[0].toUpperCase()]
    );

    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "Không tìm thấy mã nạp"
      });
    }

    const topup = result.rows[0];

    if (topup.status === "paid") {
      await client.query("COMMIT");
      return res.json({
        success: true,
        duplicate: true
      });
    }

    if (new Date(topup.expires_at) < new Date()) {
      await client.query(
        "UPDATE topups SET status='expired' WHERE id=$1",
        [topup.id]
      );

      await client.query("COMMIT");

      return res.status(410).json({
        error: "Mã nạp đã hết hạn"
      });
    }

    if (Number(topup.amount) !== amount) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Số tiền không khớp"
      });
    }

    await client.query(
      `UPDATE topups
      SET status='paid',
      sepay_transaction_id=$2,
      raw_webhook=$3,
      paid_at=NOW()
      WHERE id=$1`,
      [topup.id, txId, JSON.stringify(body)]
    );

    await client.query(
      "UPDATE users SET balance=balance+$1 WHERE id=$2",
      [amount, topup.user_id]
    );

    await client.query(
      `INSERT INTO wallet_ledger
      (user_id,topup_id,amount,description)
      VALUES($1,$2,$3,$4)`,
      [
        topup.user_id,
        topup.id,
        amount,
        "Nạp tiền " + topup.reference
      ]
    );

    await client.query("COMMIT");

    res.json({ success: true });

  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);

    res.status(500).json({
      error: "Không thể xử lý webhook"
    });

  } finally {
    client.release();
  }
});

// PUBLIC URL VALIDATION

function privateIPv4(ip) {
  const p = ip.split(".").map(Number);

  if (p.length !== 4) return true;

  return (
    p[0] === 10 ||
    p[0] === 127 ||
    p[0] === 0 ||
    p[0] === 169 && p[1] === 254 ||
    p[0] === 172 && p[1] >= 16 && p[1] <= 31 ||
    p[0] === 192 && p[1] === 168 ||
    p[0] >= 224
  );
}

function privateIPv6(ip) {
  const s = ip.toLowerCase();

  return (
    s === "::1" ||
    s === "::" ||
    s.startsWith("fc") ||
    s.startsWith("fd") ||
    s.startsWith("fe80:")
  );
}

async function validateUrl(raw) {
  let url;

  try {
    url = new URL(raw);
  } catch {
    throw new Error("URL không hợp lệ");
  }

  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  ) {
    throw new Error("Chỉ hỗ trợ URL HTTP/HTTPS công khai");
  }

  if (
    url.hostname === "localhost" ||
    url.hostname.endsWith(".localhost") ||
    url.hostname.endsWith(".local") ||
    url.hostname.endsWith(".internal")
  ) {
    throw new Error("Không cho phép mạng nội bộ");
  }

  const host = url.hostname;

  if (net.isIP(host)) {
    if (
      net.isIPv4(host) && privateIPv4(host) ||
      net.isIPv6(host) && privateIPv6(host)
    ) {
      throw new Error("IP riêng tư không được phép");
    }
  } else {
    const records = await dns.lookup(host, {
      all: true
    });

    if (
      !records.length ||
      records.some(record =>
        net.isIPv4(record.address)
          ? privateIPv4(record.address)
          : privateIPv6(record.address)
      )
    ) {
      throw new Error("Tên miền không an toàn");
    }
  }

  url.hash = "";
  return url;
}

// LINKFLOW NOVA24 BYPASS / INSPECTOR

app.post(
  "/api/resolve",
  resolveLimit,
  requireAuth,
  async (req, res) => {
    const input = String(req.body.url || "").trim();

    if (!input || input.length > 2048) {
      return res.status(400).json({
        error: "URL không hợp lệ"
      });
    }

    const max = Number(
      process.env.RESOLVER_MAX_REDIRECTS || 12
    );

    const timeout = Number(
      process.env.RESOLVER_TIMEOUT_MS || 10000
    );

    let current = input;
    const hops = [];

    const controller = new AbortController();

    const timer = setTimeout(
      () => controller.abort(),
      timeout
    );

    try {
      for (let i = 0; i <= max; i++) {
        const url = await validateUrl(current);

        const response = await fetch(url, {
          method: "GET",
          redirect: "manual",
          signal: controller.signal,
          headers: {
            "User-Agent": "LINKFLOW-NOVA24/1.0",
            "Accept": "text/html,application/xhtml+xml,*/*"
          }
        });

        const location = response.headers.get("location");

        hops.push({
          url: url.toString(),
          status: response.status,
          location: location
            ? new URL(location, url).toString()
            : null
        });

        if (
          response.status >= 300 &&
          response.status < 400 &&
          location
        ) {
          if (i === max) {
            throw new Error("Vượt giới hạn chuyển hướng");
          }

          current = new URL(location, url).toString();
          continue;
        }

        let html = "";

        try {
          if (response.body) {
            const reader = response.body.getReader();
            const { value } = await reader.read();

            if (value) {
              html = new TextDecoder().decode(
                value.slice(0, 65536)
              );
            }

            await reader.cancel();
          }
        } catch {}

        const meta = html.match(
          /<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url\s*=\s*([^"';>]+)/i
        );

        if (meta && meta[1]) {
          const next = new URL(
            meta[1].trim(),
            url
          ).toString();

          hops[hops.length - 1].clientRedirect = next;

          await validateUrl(next);

          current = next;
          continue;
        }

        return res.json({
          input,
          finalUrl: url.toString(),
          status: response.status,
          redirectCount: hops.length - 1,
          method: "HTTP + meta-refresh",
          hops,
          note: "JavaScript-only redirects and CAPTCHA are not bypassed."
        });
      }

    } catch (error) {
      res.status(400).json({
        error: error.name === "AbortError"
          ? "Hết thời gian chờ"
          : error.message,
        hops
      });

    } finally {
      clearTimeout(timer);
    }
  }
);

// ADMIN DASHBOARD API

app.get(
  "/api/admin/overview",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const [users, topups, paid] = await Promise.all([
      pool.query(
        "SELECT COUNT(*)::int AS count FROM users WHERE role='user'"
      ),
      pool.query(
        "SELECT COUNT(*)::int AS count FROM topups"
      ),
      pool.query(
        "SELECT COUNT(*)::int AS count, COALESCE(SUM(amount),0)::bigint AS amount FROM topups WHERE status='paid'"
      )
    ]);

    res.json({
      users: users.rows[0].count,
      topups: topups.rows[0].count,
      paid: paid.rows[0]
    });
  }
);

app.get(
  "/api/admin/users",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const result = await pool.query(
      "SELECT id,email,role,balance,created_at FROM users ORDER BY id DESC LIMIT 200"
    );

    res.json({ users: result.rows });
  }
);

app.get(
  "/api/admin/topups",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const result = await pool.query(
      `SELECT t.id,t.reference,t.amount,t.status,
      t.created_at,t.paid_at,u.email
      FROM topups t
      JOIN users u ON u.id=t.user_id
      ORDER BY t.id DESC LIMIT 200`
    );

    res.json({ topups: result.rows });
  }
);

app.post(
  "/api/admin/users/:id/adjust",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const amount = Number(req.body.amount);

    const description = String(
      req.body.description || "Điều chỉnh bởi admin"
    ).slice(0, 160);

    if (
      !Number.isSafeInteger(amount) ||
      amount === 0 ||
      Math.abs(amount) > 1000000000
    ) {
      return res.status(400).json({
        error: "Số tiền không hợp lệ"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const result = await client.query(
        "SELECT id,balance FROM users WHERE id=$1 FOR UPDATE",
        [req.params.id]
      );

      if (!result.rowCount) {
        throw new Error("Không tìm thấy tài khoản");
      }

      if (Number(result.rows[0].balance) + amount < 0) {
        throw new Error("Số dư không đủ");
      }

      await client.query(
        "UPDATE users SET balance=balance+$1 WHERE id=$2",
        [amount, req.params.id]
      );

      await client.query(
        `INSERT INTO wallet_ledger
        (user_id,amount,description)
        VALUES($1,$2,$3)`,
        [req.params.id, amount, description]
      );

      await client.query("COMMIT");

      res.json({ success: true });

    } catch (error) {
      await client.query("ROLLBACK");

      res.status(400).json({
        error: error.message
      });

    } finally {
      client.release();
    }
  }
);

// PAGES

app.get("/admin", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "admin.html")
  );
});

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

const port = Number(process.env.PORT || 3000);

init()
  .then(() => {
    app.listen(port, () => {
      console.log(
        "LINKFLOW NOVA24 running on port " + port
      );
    });
  })
  .catch(error => {
    console.error("Startup failed:", error);
    process.exit(1);
  });
