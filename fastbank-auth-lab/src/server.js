const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
// bcrypt is installed but NOT used in the vulnerable baseline:
const bcrypt = require("bcrypt");
const csurf = require("csurf");
const rateLimit = require("express-rate-limit");
const https = require("https");
const fs = require("fs");

const app = express();
const PORT = 8080;
const HTTPS_PORT = 3443;

app.use((req, res, next) => {
  
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'");
  
  res.setHeader("X-Frame-Options", "DENY");
  
  
  res.setHeader("X-Content-Type-Options", "nosniff");
  
  
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  
  
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  
  
  if (req.secure) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  
  
  res.removeHeader("X-Powered-By");
  
  
  if (req.path.startsWith('/api/')) {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  
  next();
});


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

const csrfProtection = csurf({ cookie: true };

const loginLimiter = rateLimit({
  windowsMs: 15 * 50 * 1000,
  max: 5,
  message: {success: false, message:"Multiple login attempts, try again later"}
});

const SALT = 12;

/**
 * VULNERABLE FAKE USER DB
 * For simplicity, we start with a single user whose password is "password123".
 * In the vulnerable version, we hash with a fast hash (SHA-256-like).
 */
const users = [
  {
    id: 1,
    username: "student",
    // VULNERABLE: fast hash without salt
    //passwordHash: fastHash("password123") // students must replace this scheme with bcrypt
    passwordHash: bcrypt.hashSync("password123", SALT)
  }
];

// In-memory session store
const sessions = {}; // token -> { userId }

/**
 * VULNERABLE FAST HASH FUNCTION (FIXED)
 * Students MUST STOP using this and replace logic with bcrypt.
 */
function generateSecureToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Home API just to show who is logged in
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

/**
 * VULNERABLE LOGIN ENDPOINT
 * - Uses fastHash instead of bcrypt
 * - Error messages leak whether username exists
 * - Session token is simple and predictable
 * - Cookie lacks security flags
 */
app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    // VULNERABLE: username enumeration via message (FIXED)
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  const match = await bcrypt.compare(password, user.passwordHash);

  if (!match) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  // VULNERABLE: predictable token (FIXED)
  const token = generateSecureToken();

  // VULNERABLE: session stored without expiration
  sessions[token] = { userId: user.id };

  // VULNERABLE: cookie without httpOnly, secure, sameSite (FIXED)
  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 24 * 50 * 50 * 1000
    // students must add: httpOnly: true, secure: true, sameSite: "lax"
  });

  // Client-side JS (login.html) will store this token in localStorage (vulnerable)
  res.json({ success: true, token });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});

try {
  const httpsOptions = {
    key: fs.readFileSync('./key.pem'),
    cert: fs.readFileSync('./cert.pem')
  };
  
  https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
    console.log(`FastBank Auth Lab (HTTPS) running at https://localhost:${HTTPS_PORT}`);
  });
} catch (err) {
  console.log('HTTPS not configured. Run the following to create certificates:');
  console.log('openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes');
}
