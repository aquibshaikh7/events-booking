import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

// Load .env (only in local dev, not in Render)
if (process.env.NODE_ENV !== "production") {
  dotenv.config();
}

const app = express();
const port = process.env.PORT || 3000;

// ================= DATABASE =================
const dbConfig = {
  connectionString:
    process.env.DATABASE_URL ||
    `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@localhost:5432/${process.env.DB_NAME}`,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
};

const db = new pg.Client(dbConfig);

db.connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => console.error("❌ DB Connection Error:", err));

// ================= APP SETUP =================
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// ================= SESSION =================
app.use(
  session({
    secret: process.env.SESSION_SECRET || "local-secret-key",
    resave: false,
    saveUninitialized: true,
  })
);

// ================= AUTH MIDDLEWARE =================
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

// ================= ROUTES =================

// Home
app.get("/", async (req, res) => {
  let events = [];
  if (req.session.user) {
    if (req.session.user.role === "admin") {
      const result = await db.query("SELECT * FROM events ORDER BY date ASC");
      events = result.rows;
    } else {
      const result = await db.query(
        "SELECT * FROM events WHERE user_id = $1 ORDER BY date ASC",
        [req.session.user.id]
      );
      events = result.rows;
    }
  }
  res.render("index", { user: req.session.user, events });
});

// Signup
app.get("/signup", (req, res) => res.render("signup"));

app.post("/signup", async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const existing = await db.query("SELECT * FROM users WHERE username=$1", [
      username,
    ]);
    if (existing.rows.length > 0) {
      return res.send(
        "⚠️ Username already taken. <a href='/signup'>Try another</a>"
      );
    }
    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3)",
      [username, hashed, role || "user"]
    );
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.send("Error occurred. Please try again.");
  }
});

// Login
app.get("/login", (req, res) => res.render("login"));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const result = await db.query("SELECT * FROM users WHERE username=$1", [
    username,
  ]);
  if (result.rows.length > 0) {
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.user = user;
      return res.redirect("/");
    }
  }
  res.send("Invalid credentials. <a href='/login'>Try again</a>");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// Create event
app.get("/create-event", requireLogin, (req, res) => {
  res.render("create-event", { user: req.session.user });
});

app.post("/create-event", requireLogin, async (req, res) => {
  const { title, date, location } = req.body;
  const userId = req.session.user.id;
  await db.query(
    "INSERT INTO events (title, date, location, user_id) VALUES ($1, $2, $3, $4)",
    [title, date, location, userId]
  );
  res.redirect("/");
});

// Book event
app.post("/book/:id", requireLogin, async (req, res) => {
  const eventId = req.params.id;
  const userId = req.session.user.id;
  await db.query("INSERT INTO bookings (user_id, event_id) VALUES ($1, $2)", [
    userId,
    eventId,
  ]);
  res.render("confirmation", { user: req.session.user, eventId });
});

// Admin
app.get("/admin", requireLogin, async (req, res) => {
  if (req.session.user.role !== "admin") return res.send("Access denied");
  const events = await db.query("SELECT * FROM events ORDER BY date ASC");
  res.render("admin", { user: req.session.user, events: events.rows });
});

app.post("/admin/add", requireLogin, async (req, res) => {
  if (req.session.user.role !== "admin") return res.send("Access denied");
  const { title, date, location } = req.body;
  await db.query(
    "INSERT INTO events (title, date, location) VALUES ($1,$2,$3)",
    [title, date, location]
  );
  res.redirect("/admin");
});

app.post("/admin/delete/:id", requireLogin, async (req, res) => {
  if (req.session.user.role !== "admin") return res.send("Access denied");
  await db.query("DELETE FROM events WHERE id=$1", [req.params.id]);
  res.redirect("/admin");
});

// ================= SERVER =================
app.listen(port, () =>
  console.log(`✅ Server running at http://localhost:${port}`)
);
