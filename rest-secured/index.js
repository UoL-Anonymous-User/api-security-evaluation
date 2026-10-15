require('dotenv').config();
const jwt = require('jsonwebtoken');
const express = require('express');
const pool = require('./db');
const bcrypt = require('bcrypt');

const app = express();

if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set.');
  process.exit(1);
}

// Security headers & body size limit (OWASP API4 & API8)
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
app.use(express.json({ limit: '10kb' }));

// Built-in memory rate limiter (OWASP API2, API4 & API6)
function createRateLimiter(windowMs, max, message) {
  const hits = new Map();
  setInterval(() => hits.clear(), windowMs).unref();

  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const count = (hits.get(ip) || 0) + 1;
    hits.set(ip, count);
    if (count > max) {
      return res.status(429).json({ message });
    }
    next();
  };
}

const globalLimiter = createRateLimiter(15 * 60 * 1000, 100, 'Too many requests, please try again later');
const authLimiter = createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts, please try again later');

app.use(globalLimiter);

const SALT_ROUNDS = 10;
const DUMMY_HASH = bcrypt.hashSync('dummy_timing_secret_value', SALT_ROUNDS);
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function parseValidId(rawId) {
  if (typeof rawId !== 'string' || !/^\d+$/.test(rawId)) return null;
  const parsed = Number.parseInt(rawId, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

// Test route
app.get('/', (req, res) => {
  res.send('My API is working 🚀');
});

// Authentication middleware
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token =
    typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
      ? authHeader.split(' ')[1]
      : null;

  if (!token) return res.status(401).json({ message: 'No token' });

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, role FROM users WHERE id = $1',
      [decoded.id]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = result.rows[0];
    next();
  } catch (err) {
    console.error('Auth error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
}

// Register route (Allows user to set 'user' or 'admin' role)
app.post('/register', authLimiter, async (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ message: 'Email and password required' });
  }

  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password.trim() : '';
  let role = typeof req.body.role === 'string' ? req.body.role.trim() : 'user';

  if (!['user', 'admin'].includes(role)) {
    role = 'user';
  }

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  if (email.length > 254 || !EMAIL_REGEX.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }

  if (Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({ message: 'Password must not exceed 72 bytes' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      'INSERT INTO users (email, password, role) VALUES ($1, $2, $3) RETURNING id, email, role',
      [email, hashedPassword, role]
    );

    res.status(201).json({
      message: 'User created successfully',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Register error:', err.message);
    if (err.code === '23505') {
      return res.status(400).json({ message: 'Email already exists' });
    }
    res.status(500).json({ message: 'Error saving user' });
  }
});

// Login route
app.post('/login', authLimiter, async (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ message: 'Email and password required' });
  }

  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password.trim() : '';

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  if (Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user ? user.password : DUMMY_HASH);
    if (!user || !isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' }
    );

    res.json({
      message: 'Login successful',
      token: token
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Profile route
app.get('/profile', authenticateToken, (req, res) => {
  res.json({
    message: 'Protected data',
    user: req.user
  });
});

// Delete user route
app.delete('/users/:id', authenticateToken, async (req, res) => {
  const targetId = parseValidId(req.params.id);
  if (!targetId) {
    return res.status(400).json({ message: 'Invalid user ID' });
  }

  if (Number(req.user.id) !== targetId && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }

  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1', [targetId]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted' });
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create order route
app.post('/orders', authenticateToken, async (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ message: 'Invalid order data' });
  }

  const { item, amount } = req.body;
  const user_id = req.user.id;

  if (
    typeof item !== 'string' ||
    item.trim().length === 0 ||
    item.trim().length > 255 ||
    typeof amount !== 'number' ||
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return res.status(400).json({ message: 'Invalid order data' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO orders (user_id, item, amount) VALUES ($1, $2, $3) RETURNING *',
      [user_id, item.trim(), amount]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create order error:', err.message);
    res.status(500).json({ message: 'Error creating order' });
  }
});

// Get orders route
app.get('/orders', authenticateToken, async (req, res) => {
  const { id, role } = req.user;
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), 100);
  const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);

  try {
    let result;
    if (role === 'admin') {
      result = await pool.query(
        'SELECT * FROM orders ORDER BY id ASC LIMIT $1 OFFSET $2',
        [limit, offset]
      );
    } else {
      result = await pool.query(
        'SELECT * FROM orders WHERE user_id = $1 ORDER BY id ASC LIMIT $2 OFFSET $3',
        [id, limit, offset]
      );
    }
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch orders error:', err.message);
    res.status(500).json({ message: 'Error fetching orders' });
  }
});

// Delete order route
app.delete('/orders/:id', authenticateToken, async (req, res) => {
  const orderId = parseValidId(req.params.id);
  if (!orderId) {
    return res.status(400).json({ message: 'Invalid order ID' });
  }

  try {
    const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }

    const order = orderResult.rows[0];
    if (Number(req.user.id) !== Number(order.user_id) && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }

    await pool.query('DELETE FROM orders WHERE id = $1', [orderId]);
    res.json({ message: 'Order deleted' });
  } catch (err) {
    console.error('Delete order error:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin route
app.get('/admin', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }
  res.json({ message: 'Welcome admin 👑' });
});

// Global error handler
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ message: 'Malformed JSON payload' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ message: 'Payload too large' });
  }
  console.error(err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});