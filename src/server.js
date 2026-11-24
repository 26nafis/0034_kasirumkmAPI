import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json());

const auth = (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    next();
  } catch {
    res.status(401).json({ message: 'Sesi tidak valid' });
  }
};

const ownerOnly = (req, res, next) => {
  if (req.user?.role !== 'OWNER') return res.status(403).json({ message: 'Akses Owner diperlukan' });
  next();
};

app.get('/api/health', async (_, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: true });
  } catch (error) {
    res.status(503).json({ ok: false, database: false, message: error.message });
  }
});

app.post('/api/auth/setup-owner', async (req, res) => {
  try {
    if (!process.env.SETUP_KEY || req.headers['x-setup-key'] !== process.env.SETUP_KEY) {
      return res.status(403).json({ message: 'Setup key salah' });
    }
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 8) {
      return res.status(400).json({ message: 'Nama, email, dan password minimal 8 karakter wajib diisi' });
    }
    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.query(
      "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'OWNER')",
      [name.trim(), email.trim().toLowerCase(), hash]
    );
    res.status(201).json({ id: result.insertId, name, email, role: 'OWNER' });
  } catch (error) {
    res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({ message: error.code === 'ER_DUP_ENTRY' ? 'Email sudah terdaftar' : error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email=?', [String(req.body.email || '').trim().toLowerCase()]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(req.body.password || '', user.password_hash))) {
      return res.status(401).json({ message: 'Email atau password salah' });
    }
    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: '8h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/categories', auth, async (_, res) => {
  try { const [rows] = await pool.query('SELECT * FROM categories ORDER BY name'); res.json(rows); }
  catch (error) { res.status(500).json({ message: error.message }); }
});

app.post('/api/categories', auth, ownerOnly, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    if (!name) return res.status(400).json({ message: 'Nama kategori wajib diisi' });
    const [result] = await pool.query('INSERT INTO categories(name) VALUES(?)', [name]);
    res.status(201).json({ id: result.insertId, name });
  } catch (error) { res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({ message: error.message }); }
});

app.get('/api/products', auth, async (_, res) => {
  try {
    const [rows] = await pool.query('SELECT p.*, c.name AS category FROM products p LEFT JOIN categories c ON c.id=p.category_id ORDER BY p.name');
    res.json(rows);
  } catch (error) { res.status(500).json({ message: error.message }); }
});

app.post('/api/products', auth, ownerOnly, async (req, res) => {
  try {
    const { code, name, categoryId, price, stock } = req.body;
    if (!code || !name || Number(price) <= 0 || Number(stock) < 0) return res.status(400).json({ message: 'Data produk tidak valid' });
    const [result] = await pool.query('INSERT INTO products(code,name,category_id,price,stock) VALUES(?,?,?,?,?)', [code, name, categoryId || null, price, stock]);
    res.status(201).json({ id: result.insertId, code, name, categoryId, price, stock });
  } catch (error) { res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({ message: error.message }); }
});

app.get('/api/transactions', auth, async (_, res) => {
  try { const [rows] = await pool.query('SELECT * FROM transactions ORDER BY created_at DESC'); res.json(rows); }
  catch (error) { res.status(500).json({ message: error.message }); }
});

// CRUD kategori lengkap
app.put('/api/categories/:id', auth, ownerOnly, async (req, res) => {
  try { await pool.query('UPDATE categories SET name=? WHERE id=?', [String(req.body.name || '').trim(), req.params.id]); res.json({ message: 'Kategori diperbarui' }); }
  catch (error) { res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({ message: error.message }); }
});
app.delete('/api/categories/:id', auth, ownerOnly, async (req, res) => {
  try { await pool.query('DELETE FROM categories WHERE id=?', [req.params.id]); res.json({ message: 'Kategori dihapus' }); }
  catch (error) { res.status(500).json({ message: error.message }); }
});

// Kelola karyawan Kasir
app.get('/api/employees', auth, ownerOnly, async (_, res) => {
  try { const [rows] = await pool.query('SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC'); res.json(rows); }
  catch (error) { res.status(500).json({ message: error.message }); }
});
app.post('/api/employees', auth, ownerOnly, async (req, res) => {
  try { const { name, email, password } = req.body; if (!name || !email || !password || password.length < 8) return res.status(400).json({ message: 'Data Kasir tidak valid' }); const hash = await bcrypt.hash(password, 12); const [r] = await pool.query("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'KASIR')", [name.trim(), email.trim().toLowerCase(), hash]); res.status(201).json({ id: r.insertId, name, email: email.trim().toLowerCase(), role: 'KASIR' }); }
  catch (error) { res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({ message: error.message }); }
});
app.delete('/api/employees/:id', auth, ownerOnly, async (req, res) => {
  try { await pool.query("DELETE FROM users WHERE id=? AND role='KASIR'", [req.params.id]); res.json({ message: 'Karyawan dihapus' }); }
  catch (error) { res.status(500).json({ message: error.message }); }
});

// CRUD produk, tambah stok
app.put('/api/products/:id', auth, ownerOnly, async (req, res) => {
  try { const { code, name, categoryId, price } = req.body; await pool.query('UPDATE products SET code=?,name=?,category_id=?,price=? WHERE id=?', [code, name, categoryId || null, price, req.params.id]); res.json({ message: 'Produk diperbarui' }); }
  catch (error) { res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({ message: error.message }); }
});
app.delete('/api/products/:id', auth, ownerOnly, async (req, res) => {
  try { await pool.query('DELETE FROM products WHERE id=?', [req.params.id]); res.json({ message: 'Produk dihapus' }); }
  catch (error) { res.status(500).json({ message: error.message }); }
});
app.post('/api/products/:id/stock', auth, ownerOnly, async (req, res) => {
  const quantity = Number(req.body.quantity); if (!Number.isInteger(quantity) || quantity <= 0) return res.status(400).json({ message: 'Jumlah stok tidak valid' });
  const conn = await pool.getConnection(); try { await conn.beginTransaction(); await conn.query('UPDATE products SET stock=stock+? WHERE id=?', [quantity, req.params.id]); await conn.query("INSERT INTO stock_movements(product_id,user_id,quantity,type,note) VALUES(?,?,?,'IN',?)", [req.params.id, req.user.id, quantity, req.body.note || 'Tambah stok']); await conn.commit(); res.json({ message: 'Stok ditambahkan' }); } catch (error) { await conn.rollback(); res.status(500).json({ message: error.message }); } finally { conn.release(); }
});

// Supplier dan pelanggan
app.get('/api/suppliers', auth, async (_, res) => { try { const [r] = await pool.query('SELECT * FROM suppliers ORDER BY name'); res.json(r); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/suppliers', auth, ownerOnly, async (req, res) => { try { const [r] = await pool.query('INSERT INTO suppliers(name,phone,product) VALUES(?,?,?)', [req.body.name, req.body.phone || null, req.body.product || null]); res.status(201).json({ id: r.insertId, ...req.body }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.put('/api/suppliers/:id', auth, ownerOnly, async (req, res) => { try { await pool.query('UPDATE suppliers SET name=?,phone=?,product=? WHERE id=?', [req.body.name, req.body.phone || null, req.body.product || null, req.params.id]); res.json({ message: 'Supplier diperbarui' }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.delete('/api/suppliers/:id', auth, ownerOnly, async (req, res) => { try { await pool.query('DELETE FROM suppliers WHERE id=?', [req.params.id]); res.json({ message: 'Supplier dihapus' }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/customers', auth, async (_, res) => { try { const [r] = await pool.query('SELECT * FROM customers ORDER BY name'); res.json(r); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/customers', auth, async (req, res) => { try { const [r] = await pool.query('INSERT INTO customers(name,phone,address) VALUES(?,?,?)', [req.body.name, req.body.phone || null, req.body.address || null]); res.status(201).json({ id: r.insertId, ...req.body }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.put('/api/customers/:id', auth, async (req, res) => { try { await pool.query('UPDATE customers SET name=?,phone=?,address=? WHERE id=?', [req.body.name, req.body.phone || null, req.body.address || null, req.params.id]); res.json({ message: 'Pelanggan diperbarui' }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.delete('/api/customers/:id', auth, async (req, res) => { try { await pool.query('DELETE FROM customers WHERE id=?', [req.params.id]); res.json({ message: 'Pelanggan dihapus' }); } catch (e) { res.status(500).json({ message: e.message }); } });

// Transaksi, detail, riwayat, dan laporan
app.post('/api/transactions', auth, async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : []; if (!items.length) return res.status(400).json({ message: 'Keranjang kosong' });
  const conn = await pool.getConnection(); try { await conn.beginTransaction(); let total = 0; const checked = []; for (const item of items) { const [rows] = await conn.query('SELECT * FROM products WHERE id=? FOR UPDATE', [item.productId]); const p = rows[0]; const q = Number(item.quantity); if (!p || !Number.isInteger(q) || q <= 0 || p.stock < q) throw new Error(`Stok tidak cukup untuk ${p?.name || 'produk'}`); const subtotal = Number(p.price) * q; total += subtotal; checked.push({ p, q, subtotal }); } const number = `TRX-${Date.now()}`; const [t] = await conn.query('INSERT INTO transactions(number,user_id,customer_id,total) VALUES(?,?,?,?)', [number, req.user.id, req.body.customerId || null, total]); for (const x of checked) { await conn.query('INSERT INTO transaction_items(transaction_id,product_id,quantity,price,subtotal) VALUES(?,?,?,?,?)', [t.insertId, x.p.id, x.q, x.p.price, x.subtotal]); await conn.query('UPDATE products SET stock=stock-? WHERE id=?', [x.q, x.p.id]); await conn.query("INSERT INTO stock_movements(product_id,user_id,quantity,type,note) VALUES(?,?,?,'OUT',?)", [x.p.id, req.user.id, x.q, number]); } await conn.commit(); res.status(201).json({ id: t.insertId, number, total }); } catch (error) { await conn.rollback(); res.status(400).json({ message: error.message }); } finally { conn.release(); }
});
app.get('/api/transactions/:id', auth, async (req, res) => { try { const [t] = await pool.query('SELECT t.*,u.name AS cashier,c.name AS customer FROM transactions t JOIN users u ON u.id=t.user_id LEFT JOIN customers c ON c.id=t.customer_id WHERE t.id=?', [req.params.id]); const [items] = await pool.query('SELECT ti.*,p.name,p.code FROM transaction_items ti JOIN products p ON p.id=ti.product_id WHERE ti.transaction_id=?', [req.params.id]); if (!t[0]) return res.status(404).json({ message: 'Transaksi tidak ditemukan' }); res.json({ ...t[0], items }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/reports/sales', auth, async (req, res) => { try { const from = req.query.from || '1970-01-01', to = req.query.to || '2999-12-31'; const [[summary]] = await pool.query('SELECT COUNT(*) transactionCount,COALESCE(SUM(total),0) totalSales FROM transactions WHERE DATE(created_at) BETWEEN ? AND ?', [from, to]); const [daily] = await pool.query('SELECT DATE(created_at) date,COUNT(*) transactions,SUM(total) total FROM transactions WHERE DATE(created_at) BETWEEN ? AND ? GROUP BY DATE(created_at) ORDER BY date', [from, to]); res.json({ from, to, summary, daily }); } catch (e) { res.status(500).json({ message: e.message }); } });

app.listen(Number(process.env.PORT || 3000), '0.0.0.0', () => {
  console.log(`KasirUMKM API berjalan di port ${process.env.PORT || 3000}`);
});