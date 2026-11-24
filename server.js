require("dotenv").config();

const express = require("express");
const session = require("express-session");
const { google } = require("googleapis");
const multer = require("multer");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs/promises");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const DATA_DIR = path.join(ROOT, "data", "users");
const MAX_FILE_SIZE = Number(process.env.MAX_FILE_SIZE || 10 * 1024 * 1024);
const MAX_FILES = Number(process.env.MAX_FILES || 10);

if (!process.env.SESSION_SECRET) {
  throw new Error("Falta SESSION_SECRET en el archivo .env");
}
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  throw new Error("Faltan GOOGLE_CLIENT_ID o GOOGLE_CLIENT_SECRET en .env");
}

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`
);

app.disable("x-powered-by");
app.use(helmet({
  // La aplicación sirve HTML propio y no necesita cargar scripts externos.
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "1mb" }));
app.use(session({
  name: "tradicionessid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// IMPORTANTE: solo se publica la carpeta public. data/ nunca se expone como contenido estático.
app.use(express.static(PUBLIC_DIR));

function safeUserFolder(userId) {
  // No se usa el email ni un valor enviado por el navegador para construir rutas.
  return crypto.createHash("sha256").update(String(userId)).digest("hex");
}

function userPaths(req) {
  if (!req.session.user || !req.session.user.id) {
    throw new Error("UNAUTHENTICATED");
  }
  const folder = path.join(DATA_DIR, safeUserFolder(req.session.user.id));
  return {
    folder,
    json: path.join(folder, "records.json"),
    uploads: path.join(folder, "uploads")
  };
}

async function ensureUserFiles(req) {
  const p = userPaths(req);
  await fs.mkdir(p.uploads, { recursive: true });
  try {
    await fs.access(p.json);
  } catch {
    await writeJsonAtomic(p.json, {
      user: {
        id: req.session.user.id,
        email: req.session.user.email || null
      },
      records: []
    });
  }
  return p;
}

async function readJson(file) {
  try {
    const raw = await fs.readFile(file, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.records)) throw new Error("Formato JSON no válido");
    return parsed;
  } catch (err) {
    if (err.code === "ENOENT") return { records: [] };
    throw err;
  }
}

async function writeJsonAtomic(file, value) {
  const temp = `${file}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(temp, JSON.stringify(value, null, 2), { encoding: "utf8", mode: 0o600 });
  await fs.rename(temp, file);
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Inicia sesión para continuar." });
  next();
}

function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      const p = await ensureUserFiles(req);
      cb(null, p.uploads);
    } catch (err) {
      cb(err);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").slice(0, 12).replace(/[^.a-zA-Z0-9]/g, "");
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES }
});

// Login Google
app.get("/auth/google", (req, res) => {
  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["openid", "email", "profile"],
    state
  });
  res.redirect(url);
});

app.get("/auth/google/callback", asyncRoute(async (req, res) => {
  if (!req.query.code || !req.query.state || req.query.state !== req.session.oauthState) {
    return res.status(400).send("Error de autenticación: estado OAuth no válido.");
  }
  delete req.session.oauthState;

  const { tokens } = await oauth2Client.getToken(String(req.query.code));
  oauth2Client.setCredentials(tokens);
  const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
  const { data } = await oauth2.userinfo.get();

  if (!data.id || !data.email) {
    return res.status(401).send("Google no ha devuelto una identidad válida.");
  }

  req.session.user = {
    id: data.id,
    email: data.email,
    name: data.name || "",
    picture: data.picture || ""
  };

  // Rotación de sesión tras autenticación.
  req.session.regenerate((err) => {
    if (err) return res.status(500).send("No se pudo iniciar la sesión.");
    req.session.user = {
      id: data.id,
      email: data.email,
      name: data.name || "",
      picture: data.picture || ""
    };
    req.session.save((saveErr) => {
      if (saveErr) return res.status(500).send("No se pudo guardar la sesión.");
      res.redirect("/");
    });
  });
}));

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("tradicionessid");
    res.json({ ok: true });
  });
});

// Lista solo los registros del usuario autenticado.
app.get("/api/records", requireAuth, asyncRoute(async (req, res) => {
  const p = await ensureUserFiles(req);
  const data = await readJson(p.json);
  res.json({ records: data.records });
}));

// Crea/actualiza un registro. Acepta JSON normal o multipart con:
// campo "record" (JSON) y archivos opcionales "files".
app.post("/api/records", requireAuth, upload.array("files", MAX_FILES), asyncRoute(async (req, res) => {
  let record;
  try {
    record = typeof req.body.record === "string" ? JSON.parse(req.body.record) : req.body;
  } catch {
    return res.status(400).json({ error: "El campo record no contiene JSON válido." });
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return res.status(400).json({ error: "Registro no válido." });
  }

  const p = await ensureUserFiles(req);
  const data = await readJson(p.json);
  const id = String(record.id || crypto.randomUUID());
  const previous = data.records.find(r => String(r.id) === id);

  const newFiles = (req.files || []).map(file => ({
    id: path.basename(file.filename, path.extname(file.filename)),
    filename: file.filename,
    name: file.originalname,
    mimeType: file.mimetype,
    size: file.size,
    url: `/api/files/${encodeURIComponent(id)}/${encodeURIComponent(file.filename)}`
  }));

  const cleanRecord = {
    ...record,
    id,
    attachments: [
      ...(Array.isArray(record.attachments) ? record.attachments : (previous?.attachments || [])),
      ...newFiles
    ]
  };

  const index = data.records.findIndex(r => String(r.id) === id);
  if (index >= 0) data.records[index] = cleanRecord;
  else data.records.push(cleanRecord);

  await writeJsonAtomic(p.json, {
    user: { id: req.session.user.id, email: req.session.user.email || null },
    records: data.records
  });
  res.json({ record: cleanRecord, records: data.records });
}));

// Descarga/visualización de adjuntos: exige sesión y comprueba que el archivo
// pertenece a un registro del usuario actual.
app.get("/api/files/:recordId/:filename", requireAuth, asyncRoute(async (req, res) => {
  const p = await ensureUserFiles(req);
  const data = await readJson(p.json);
  const record = data.records.find(r => String(r.id) === String(req.params.recordId));
  const attachment = record && (record.attachments || []).find(a => a.filename === req.params.filename);
  if (!attachment) return res.status(404).json({ error: "Archivo no encontrado." });

  const filename = path.basename(attachment.filename);
  const fullPath = path.join(p.uploads, filename);
  res.setHeader("Content-Type", attachment.mimeType || "application/octet-stream");
  res.setHeader("Content-Disposition", `inline; filename*=UTF-8''${encodeURIComponent(attachment.name || filename)}`);
  res.sendFile(fullPath, err => {
    if (err && !res.headersSent) res.status(err.statusCode || 404).end();
  });
}));

app.delete("/api/records/:id", requireAuth, asyncRoute(async (req, res) => {
  const p = await ensureUserFiles(req);
  const data = await readJson(p.json);
  const record = data.records.find(r => String(r.id) === String(req.params.id));
  if (!record) return res.status(404).json({ error: "Registro no encontrado." });

  // Borra adjuntos asociados, pero solo dentro de la carpeta privada del usuario.
  for (const attachment of (record.attachments || [])) {
    if (attachment.filename) {
      await fs.rm(path.join(p.uploads, path.basename(attachment.filename)), { force: true });
    }
  }
  data.records = data.records.filter(r => String(r.id) !== String(req.params.id));
  await writeJsonAtomic(p.json, {
    user: { id: req.session.user.id, email: req.session.user.email || null },
    records: data.records
  });
  res.json({ ok: true, records: data.records });
}));

app.use((err, req, res, next) => {
  console.error(err);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Error al subir archivos: ${err.message}` });
  }
  if (err.message === "UNAUTHENTICATED") return res.status(401).json({ error: "No autenticado." });
  res.status(500).json({ error: "Error interno del servidor." });
});

app.listen(PORT, () => {
  console.log(`Tradicions de Mataró disponible en http://localhost:${PORT}`);
});
