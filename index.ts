// ============================================================
// HIGH WAY RENT A CAR — REST API Server
// Deploy on Render: https://render.com
// ============================================================
// Run: npm install && npm start
// ============================================================

import express from "express";
import cors    from "cors";
import bcrypt  from "bcryptjs";
import jwt     from "jsonwebtoken";
import fs      from "fs";
import path    from "path";
import { v4 as uuidv4 } from "uuid";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = process.env.PORT || 5000;

const JWT_SECRET     = process.env.JWT_SECRET     || "highway_secret_key_2024";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*").split(",");
const DATA_FILE = path.join(__dirname, "data", "cars.json");

// ── Middleware ───────────────────────────────────────────────
app.use(express.json());
app.use(cors({
  origin: (origin: string | undefined, cb: (err: Error | null, ok?: boolean) => void) => {
    if (!origin || ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)) {
      cb(null, true);
    } else {
      cb(new Error("CORS blocked"));
    }
  },
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
}));

// ── Types ────────────────────────────────────────────────────
interface Car {
  id: string;
  name: string; nameAr: string;
  brand: string; model: string; year: number;
  category: string; categoryAr: string;
  fuel: string; fuelAr: string;
  transmission: string; transmissionAr: string;
  seats: number; doors: number; engine: string;
  color: string; colorAr: string;
  dailyPrice: number; weeklyPrice: number; monthlyPrice: number;
  image: string; images: string[];
  available: boolean; popular: boolean;
  rating: number; reviewCount: number;
  features: string[]; featuresAr: string[];
  description: string; descriptionAr: string;
  createdAt?: string; updatedAt?: string;
}

// ── Data helpers ─────────────────────────────────────────────
function readCars(): Car[] {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); }
  catch { return []; }
}
function writeCars(cars: Car[]): void {
  fs.writeFileSync(DATA_FILE, JSON.stringify(cars, null, 2), "utf8");
}

// ── Auth middleware ──────────────────────────────────────────
function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) { res.status(401).json({ error: "No token" }); return; }
  try {
    (req as any).admin = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: "Invalid token" }); }
}

// ══════════════════════════════════════════════════════════════
// PUBLIC ROUTES
// ══════════════════════════════════════════════════════════════

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// All available cars → main website
app.get("/api/cars", (_req, res) => {
  res.json(readCars().filter(c => c.available !== false));
});

// Single car
app.get("/api/cars/:id", (req, res) => {
  const car = readCars().find(c => c.id === req.params.id);
  if (!car) { res.status(404).json({ error: "Not found" }); return; }
  res.json(car);
});

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) { res.status(400).json({ error: "Required" }); return; }
  if (username !== ADMIN_USERNAME) { res.status(401).json({ error: "Invalid credentials" }); return; }

  const match = password === ADMIN_PASSWORD ||
    (ADMIN_PASSWORD.startsWith("$2") && await bcrypt.compare(password, ADMIN_PASSWORD));
  if (!match) { res.status(401).json({ error: "Invalid credentials" }); return; }

  const token = jwt.sign({ username, role: "admin" }, JWT_SECRET, { expiresIn: "24h" });
  res.json({ token, username, role: "admin" });
});

// ══════════════════════════════════════════════════════════════
// ADMIN ROUTES (protected)
// ══════════════════════════════════════════════════════════════

// All cars (including hidden)
app.get("/api/admin/cars", requireAuth, (_req, res) => res.json(readCars()));

// Stats
app.get("/api/admin/stats", requireAuth, (_req, res) => {
  const cars = readCars();
  res.json({
    totalCars:     cars.length,
    availableCars: cars.filter(c => c.available).length,
    hiddenCars:    cars.filter(c => !c.available).length,
    categories:    [...new Set(cars.map(c => c.category))].length,
    brands:        [...new Set(cars.map(c => c.brand))].length,
  });
});

// Add car
app.post("/api/admin/cars", requireAuth, (req, res) => {
  const cars = readCars();
  if (!req.body.name || !req.body.dailyPrice) {
    res.status(400).json({ error: "name and dailyPrice are required" }); return;
  }
  const car: Car = { id: uuidv4(), ...req.body, createdAt: new Date().toISOString() };
  cars.push(car);
  writeCars(cars);
  res.status(201).json(car);
});

// Update car
app.put("/api/admin/cars/:id", requireAuth, (req, res) => {
  const cars = readCars();
  const idx  = cars.findIndex(c => c.id === req.params.id);
  if (idx === -1) { res.status(404).json({ error: "Not found" }); return; }
  cars[idx] = { ...cars[idx], ...req.body, id: cars[idx].id, updatedAt: new Date().toISOString() };
  writeCars(cars);
  res.json(cars[idx]);
});

// Update prices only
app.patch("/api/admin/cars/:id/prices", requireAuth, (req, res) => {
  const cars = readCars();
  const idx  = cars.findIndex(c => c.id === req.params.id);
  if (idx === -1) { res.status(404).json({ error: "Not found" }); return; }
  const { dailyPrice, weeklyPrice, monthlyPrice } = req.body;
  if (dailyPrice   !== undefined) cars[idx].dailyPrice   = Number(dailyPrice);
  if (weeklyPrice  !== undefined) cars[idx].weeklyPrice  = Number(weeklyPrice);
  if (monthlyPrice !== undefined) cars[idx].monthlyPrice = Number(monthlyPrice);
  cars[idx].updatedAt = new Date().toISOString();
  writeCars(cars);
  res.json(cars[idx]);
});

// Toggle visibility
app.patch("/api/admin/cars/:id/toggle", requireAuth, (req, res) => {
  const cars = readCars();
  const idx  = cars.findIndex(c => c.id === req.params.id);
  if (idx === -1) { res.status(404).json({ error: "Not found" }); return; }
  cars[idx].available = !cars[idx].available;
  writeCars(cars);
  res.json({ id: cars[idx].id, available: cars[idx].available });
});

// Duplicate car
app.post("/api/admin/cars/:id/duplicate", requireAuth, (req, res) => {
  const cars = readCars();
  const car  = cars.find(c => c.id === req.params.id);
  if (!car) { res.status(404).json({ error: "Not found" }); return; }
  const copy = { ...car, id: uuidv4(), name: car.name + " (Copy)", nameAr: car.nameAr + " (نسخة)", createdAt: new Date().toISOString() };
  cars.push(copy);
  writeCars(cars);
  res.status(201).json(copy);
});

// Delete car
app.delete("/api/admin/cars/:id", requireAuth, (req, res) => {
  const cars = readCars();
  const next = cars.filter(c => c.id !== req.params.id);
  if (next.length === cars.length) { res.status(404).json({ error: "Not found" }); return; }
  writeCars(next);
  res.json({ message: "Deleted" });
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  const dir = path.join(__dirname, "data");
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) writeCars([]);
  console.log(`✅  Highway API running on port ${PORT}`);
});
