import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

// Load env variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// PostgreSQL connection
const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
db.connect();

// View engine + middleware
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

// Middleware: check login
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

// ================= ROUTES =================

// Home page (events list)
app.get("/", async (req, res) => {
  let events;

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
  } else {
    events = [];
  }

  res.render("index", { user: req.session.user, events });
});

// ================= AUTH =================

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

// ================= EVENTS =================

// Create event (user)
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

// ================= ADMIN =================

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
