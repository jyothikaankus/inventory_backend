// Complete Express API for Lost and Found Inventory Management System

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');

app.use(express.json());
app.use(cors());

const pool = new Pool({
  user: 'jyothikaa',
  host: 'dpg-cvsuuq49c44c73c7aa90-a.virginia-postgres.render.com',
  database: 'inventory_database_3oqj',
  password: 't85L6CZ4FXRFZW7xj1oiOePcPFLB3w0L',
  port: 5432, 
  ssl: {
    rejectUnauthorized: false, // ⛔ Don't verify the SSL cert
  },
});

const SECRET_KEY = 'your_secret_key';

// ---------- Middleware ----------
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ---------- Authentication ----------
app.post('/api/auth/register', async (req, res) => {
  const { name='surya', email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query('INSERT INTO users(name, email, password) VALUES($1, $2, $3) RETURNING *', [name, email, hash]);
  res.json(result.rows[0]);
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = result.rows[0];
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ userId: user.user_id, role: user.role }, SECRET_KEY);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/api/auth/profile', authenticate, async (req, res) => {
  const result = await pool.query('SELECT * FROM users WHERE user_id=$1', [req.user.userId]);
  res.json(result.rows[0]);
});

// ---------- Users ----------
app.get('/api/users/:id', authenticate, async (req, res) => {
  const result = await pool.query('SELECT * FROM users WHERE user_id=$1', [req.params.id]);
  res.json(result.rows[0]);
});

app.put('/api/users/:id', authenticate, async (req, res) => {
  const { name, email } = req.body;
  const result = await pool.query('UPDATE users SET name=$1, email=$2 WHERE user_id=$3 RETURNING *', [name, email, req.params.id]);
  res.json(result.rows[0]);
});

app.delete('/api/users/:id', authenticate, async (req, res) => {
  await pool.query('DELETE FROM users WHERE user_id=$1', [req.params.id]);
  res.json({ message: 'User deleted' });
});

// ---------- Items ----------
app.post('/api/items', authenticate, async (req, res) => {
  const { name, description, category, location, date_lost_or_found, type } = req.body;
  const result = await pool.query(
    'INSERT INTO items(user_id, name, description, category, location, date_lost_or_found, type) VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING *',
    [req.user.userId, name, description, category, location, date_lost_or_found, type]
  );
  res.json(result.rows[0]);
});

app.get('/api/items', async (req, res) => {
  const result = await pool.query('SELECT * FROM items');
  res.json(result.rows);
});

app.get('/api/items/:id', async (req, res) => {
  const result = await pool.query('SELECT * FROM items WHERE item_id=$1', [req.params.id]);
  res.json(result.rows[0]);
});

app.put('/api/items/:id', authenticate, async (req, res) => {
  const { name, description, category, location, date_lost_or_found, type } = req.body;
  const result = await pool.query(
    'UPDATE items SET name=$1, description=$2, category=$3, location=$4, date_lost_or_found=$5, type=$6 WHERE item_id=$7 RETURNING *',
    [name, description, category, location, date_lost_or_found, type, req.params.id]
  );
  res.json(result.rows[0]);
});

app.delete('/api/items/:id', authenticate, async (req, res) => {
  await pool.query('DELETE FROM items WHERE item_id=$1', [req.params.id]);
  res.json({ message: 'Item deleted' });
});

// ---------- Claims ----------
app.post('/api/claims', authenticate, async (req, res) => {
  const { item_id } = req.body;
  const result = await pool.query('INSERT INTO claims(user_id, item_id) VALUES($1, $2) RETURNING *', [req.user.userId, item_id]);
  res.json(result.rows[0]);
});

app.get('/api/claims', authenticate, async (req, res) => {
  const result = await pool.query('SELECT * FROM claims');
  res.json(result.rows);
});

app.get('/api/claims/user/:userId', authenticate, async (req, res) => {
  const result = await pool.query('SELECT * FROM claims WHERE user_id=$1', [req.params.userId]);
  res.json(result.rows);
});

app.get('/api/claims/:claimId', authenticate, async (req, res) => {
  const result = await pool.query('SELECT * FROM claims WHERE claim_id=$1', [req.params.claimId]);
  res.json(result.rows[0]);
});

app.put('/api/claims/:claimId', authenticate, async (req, res) => {
  const { status } = req.body;
  const result = await pool.query('UPDATE claims SET status=$1 WHERE claim_id=$2 RETURNING *', [status, req.params.claimId]);
  res.json(result.rows[0]);
});

// ---------- Document Upload ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

app.post('/api/documents', authenticate, upload.single('document'), async (req, res) => {
  const { claim_id } = req.body;
  const result = await pool.query('INSERT INTO documents(claim_id, file_name, file_url) VALUES($1, $2, $3) RETURNING *', [claim_id, req.file.filename, req.file.path]);
  res.json(result.rows[0]);
});

app.get('/api/documents/:claimId', authenticate, async (req, res) => {
  const result = await pool.query('SELECT * FROM documents WHERE claim_id=$1', [req.params.claimId]);
  res.json(result.rows);
});

app.delete('/api/documents/:documentId', authenticate, async (req, res) => {
  await pool.query('DELETE FROM documents WHERE document_id=$1', [req.params.documentId]);
  res.json({ message: 'Document deleted' });
});

// ---------- Match Suggestions ----------
app.get('/api/matches/:itemId', authenticate, async (req, res) => {
  const result = await pool.query('SELECT * FROM matches WHERE lost_item_id=$1 OR found_item_id=$1', [req.params.itemId]);
  res.json(result.rows);
});

app.post('/api/matches/manual', authenticate, async (req, res) => {
  const { lost_item_id, found_item_id } = req.body;
  const result = await pool.query('INSERT INTO matches(lost_item_id, found_item_id) VALUES($1, $2) RETURNING *', [lost_item_id, found_item_id]);
  res.json(result.rows[0]);
});

// ---------- Start Server ----------
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
