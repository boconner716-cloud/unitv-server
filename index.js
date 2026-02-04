import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { db, initDb } from "./db.js";

const app = express();
app.use(cors());
app.use(express.json());

initDb();

function signToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, plan: user.plan, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Sem token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password)
    return res.status(400).json({ error: "Dados inválidos" });

  if (String(password).length < 6)
    return res.status(400).json({ error: "Senha mínima: 6" });

  const password_hash = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)`,
    [name.trim(), email.trim().toLowerCase(), password_hash],
    function (err) {
      if (err) {
        if (String(err).includes("UNIQUE"))
          return res.status(409).json({ error: "E-mail já existe" });

        return res.status(500).json({ error: "Erro no servidor" });
      }

      const user = {
        id: this.lastID,
        name,
        email: email.toLowerCase(),
        plan: "FREE"
      };

      return res.json({ token: signToken(user), user });
    }
  );
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "Dados inválidos" });

  db.get(
    `SELECT id, name, email, password_hash, plan
     FROM users WHERE email = ?`,
    [email.trim().toLowerCase()],
    async (err, row) => {
      if (err)
        return res.status(500).json({ error: "Erro no servidor" });

      if (!row)
        return res.status(401).json({ error: "Login inválido" });

      const ok = await bcrypt.compare(password, row.password_hash);
      if (!ok)
        return res.status(401).json({ error: "Login inválido" });

      const user = {
        id: row.id,
        name: row.name,
        email: row.email,
        plan: row.plan
      };

      return res.json({ token: signToken(user), user });
    }
  );
});

app.get("/me", auth, (req, res) => {
  db.get(
    `SELECT id, name, email, plan, created_at
     FROM users WHERE id = ?`,
    [req.user.sub],
    (err, row) => {
      if (err)
        return res.status(500).json({ error: "Erro no servidor" });

      if (!row)
        return res.status(404).json({ error: "Usuário não encontrado" });

      return res.json({ user: row });
    }
  );
});

app.post("/me/upgrade", auth, (req, res) => {
  db.run(
    `UPDATE users SET plan = 'PREMIUM' WHERE id = ?`,
    [req.user.sub],
    (err) => {
      if (err)
        return res.status(500).json({ error: "Erro no servidor" });

      return res.json({ ok: true, plan: "PREMIUM" });
    }
  );
});

const port = Number(process.env.PORT || 3333);

app.listen(port, () => {
  console.log(`API rodando em http://localhost:${port}`);
});
