import grpc from "@grpc/grpc-js";
import pool from "./db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import validator from "validator";

// Fail fast if JWT_SECRET is missing or weak
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET environment variable must be defined and at least 32 characters long");
}

// Security: Bounded in-memory rate limiter with IP extraction and eviction
const rateLimits = new Map();
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 60 * 1000; // 1 minute
const MAX_MAP_SIZE = 10000;

function extractIp(peer = "") {
  if (peer.startsWith("ipv6:")) {
    const match = peer.match(/^ipv6:\[([^\]]+)\]/);
    return match ? match[1] : peer;
  }
  const cleaned = peer.replace(/^ipv4:/, "");
  return cleaned.split(":")[0] || "unknown";
}

function isRateLimited(key) {
  const now = Date.now();
  const record = rateLimits.get(key);

  if (!record || now - record.startTime > WINDOW_MS) {
    if (rateLimits.size >= MAX_MAP_SIZE) {
      const oldestKey = rateLimits.keys().next().value;
      rateLimits.delete(oldestKey);
    }
    rateLimits.set(key, { count: 1, startTime: now });
    return false;
  }

  record.count++;
  return record.count > MAX_ATTEMPTS;
}

function grpcError(code, message) {
  return { code, message };
}

function getPaginationBounds(request) {
  const rawLimit = Number.isInteger(request.limit) && request.limit !== 0 ? request.limit : 10;
  const limit = Math.min(Math.max(rawLimit, 1), 50);

  const rawOffset = Number.isInteger(request.offset) ? request.offset : 0;
  const offset = Math.max(rawOffset, 0);

  return { limit, offset };
}

// Security: Precomputed bcrypt hash (cost factor 10) to prevent timing attacks
const DUMMY_HASH = "$2b$10$7EqJtq98hPqEX7fNZaFWoO5vJc0P5V1H2Jt5Xy1s2t3u4v5w6x7y8";

function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
    });
  } catch {
    return null;
  }
}

async function getAuthenticatedUser(call) {
  const authValues = call.metadata.get("authorization");
  const authHeader = authValues.length > 0 ? authValues[0] : null;

  if (!authHeader || typeof authHeader !== "string") {
    return null;
  }

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.substring(7)
    : authHeader;

  const payload = verifyToken(token);
  if (!payload || !payload.id) {
    return null;
  }

  // Verify user still exists and fetch live role from DB
  const result = await pool.query(
    `
    SELECT id, email, role
    FROM users
    WHERE id = $1
    `,
    [payload.id]
  );

  return result.rows[0] || null;
}

export async function Register(call, callback) {
  const clientIp = extractIp(call.getPeer());
  if (isRateLimited(`reg:${clientIp}`)) {
    return callback(
      grpcError(grpc.status.RESOURCE_EXHAUSTED, "Too many requests, please try again later")
    );
  }

  let { email, password } = call.request;

  if (!email || typeof email !== "string" || email.length > 254 || !validator.isEmail(email)) {
    return callback(
      grpcError(grpc.status.INVALID_ARGUMENT, "Invalid email format")
    );
  }

  if (!password || typeof password !== "string" || password.length < 8 || password.length > 72) {
    return callback(
      grpcError(grpc.status.INVALID_ARGUMENT, "Password must be between 8 and 72 characters")
    );
  }

  email = validator.normalizeEmail(email);

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (email, password, role)
      VALUES ($1, $2, 'user')
      RETURNING id, email, role
      `,
      [email, hashedPassword]
    );

    callback(null, result.rows[0]);
  } catch (err) {
    // Avoid explicit email enumeration or raw DB leakage
    callback(
      grpcError(grpc.status.ABORTED, "Registration failed")
    );
  }
}

export async function Login(call, callback) {
  const clientIp = extractIp(call.getPeer());
  let { email, password } = call.request;

  if (!email || typeof email !== "string" || email.length > 254 || !validator.isEmail(email)) {
    return callback(
      grpcError(grpc.status.UNAUTHENTICATED, "Invalid credentials")
    );
  }

  email = validator.normalizeEmail(email);

  // Security: Block excessive requests per IP and per account
  if (isRateLimited(`login_ip:${clientIp}`) || isRateLimited(`login_user:${email}`)) {
    return callback(
      grpcError(grpc.status.RESOURCE_EXHAUSTED, "Too many requests, please try again later")
    );
  }

  if (!password || typeof password !== "string" || password.length > 72) {
    return callback(
      grpcError(grpc.status.UNAUTHENTICATED, "Invalid credentials")
    );
  }

  try {
    const result = await pool.query(
      `
      SELECT id, email, password, role
      FROM users
      WHERE email = $1
      `,
      [email]
    );

    const user = result.rows[0];

    // Security: Always run bcrypt to normalize execution time
    const hashToCompare = user ? user.password : DUMMY_HASH;
    const validPassword = await bcrypt.compare(password, hashToCompare);

    if (!user || !validPassword) {
      return callback(
        grpcError(grpc.status.UNAUTHENTICATED, "Invalid credentials")
      );
    }

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
      },
      process.env.JWT_SECRET,
      {
        algorithm: "HS256",
        expiresIn: "1h",
      }
    );

    callback(null, {
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    callback(
      grpcError(grpc.status.INTERNAL, "Internal server error")
    );
  }
}

export async function GetUsers(call, callback) {
  try {
    const user = await getAuthenticatedUser(call);

    if (!user) {
      return callback(
        grpcError(grpc.status.UNAUTHENTICATED, "Authentication required")
      );
    }

    if (user.role !== "admin") {
      return callback(
        grpcError(grpc.status.PERMISSION_DENIED, "Unauthorized")
      );
    }

    const { limit, offset } = getPaginationBounds(call.request);

    const result = await pool.query(
      `
      SELECT id, email, role
      FROM users
      ORDER BY id
      LIMIT $1 OFFSET $2
      `,
      [limit, offset]
    );

    callback(null, {
      users: result.rows,
    });
  } catch (err) {
    callback(
      grpcError(grpc.status.INTERNAL, "Internal server error")
    );
  }
}

export async function GetCurrentUser(call, callback) {
  try {
    const user = await getAuthenticatedUser(call);

    if (!user) {
      return callback(
        grpcError(grpc.status.UNAUTHENTICATED, "Authentication required")
      );
    }

    callback(null, user);
  } catch (err) {
    callback(
      grpcError(grpc.status.INTERNAL, "Internal server error")
    );
  }
}

export async function GetOrders(call, callback) {
  try {
    const user = await getAuthenticatedUser(call);

    if (!user) {
      return callback(
        grpcError(grpc.status.UNAUTHENTICATED, "Authentication required")
      );
    }

    const { limit, offset } = getPaginationBounds(call.request);

    if (user.role === "admin") {
      const result = await pool.query(
        `
        SELECT id, user_id, item, amount
        FROM orders
        ORDER BY id
        LIMIT $1 OFFSET $2
        `,
        [limit, offset]
      );
      return callback(null, { orders: result.rows });
    }

    const result = await pool.query(
      `
      SELECT id, user_id, item, amount
      FROM orders
      WHERE user_id = $1
      ORDER BY id
      LIMIT $2 OFFSET $3
      `,
      [user.id, limit, offset]
    );

    callback(null, {
      orders: result.rows,
    });
  } catch (err) {
    callback(
      grpcError(grpc.status.INTERNAL, "Internal server error")
    );
  }
}

export async function GetOrder(call, callback) {
  try {
    const user = await getAuthenticatedUser(call);

    if (!user) {
      return callback(
        grpcError(grpc.status.UNAUTHENTICATED, "Authentication required")
      );
    }

    const orderId = Number(call.request.id);
    if (!Number.isInteger(orderId) || orderId <= 0) {
      return callback(
        grpcError(grpc.status.INVALID_ARGUMENT, "Invalid order ID")
      );
    }

    let result;
    if (user.role === "admin") {
      result = await pool.query(
        `
        SELECT id, user_id, item, amount
        FROM orders
        WHERE id = $1
        `,
        [orderId]
      );
    } else {
      result = await pool.query(
        `
        SELECT id, user_id, item, amount
        FROM orders
        WHERE id = $1
        AND user_id = $2
        `,
        [orderId, user.id]
      );
    }

    if (result.rows.length === 0) {
      return callback(
        grpcError(grpc.status.NOT_FOUND, "Order not found")
      );
    }

    callback(null, result.rows[0]);
  } catch (err) {
    callback(
      grpcError(grpc.status.INTERNAL, "Internal server error")
    );
  }
}

export async function CreateOrder(call, callback) {
  try {
    const user = await getAuthenticatedUser(call);

    if (!user) {
      return callback(
        grpcError(grpc.status.UNAUTHENTICATED, "Authentication required")
      );
    }

    if (isRateLimited(`order_create:${user.id}`)) {
      return callback(
        grpcError(grpc.status.RESOURCE_EXHAUSTED, "Too many requests, please try again later")
      );
    }

    const rawItem = typeof call.request.item === "string" ? call.request.item.trim() : "";
    if (!rawItem || rawItem.length > 200) {
      return callback(
        grpcError(grpc.status.INVALID_ARGUMENT, "Item name must be between 1 and 200 characters")
      );
    }

    const amount = Number(call.request.amount);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) {
      return callback(
        grpcError(grpc.status.INVALID_ARGUMENT, "Amount must be a positive number within valid bounds")
      );
    }

    const safeItem = validator.escape(rawItem);

    const result = await pool.query(
      `
      INSERT INTO orders
      (user_id, item, amount)
      VALUES ($1, $2, $3)
      RETURNING id, user_id, item, amount
      `,
      [user.id, safeItem, amount]
    );

    callback(null, result.rows[0]);
  } catch (err) {
    callback(
      grpcError(grpc.status.INTERNAL, "Internal server error")
    );
  }
}

export async function DeleteOrder(call, callback) {
  try {
    const user = await getAuthenticatedUser(call);

    if (!user) {
      return callback(
        grpcError(grpc.status.UNAUTHENTICATED, "Authentication required")
      );
    }

    const orderId = Number(call.request.id);
    if (!Number.isInteger(orderId) || orderId <= 0) {
      return callback(
        grpcError(grpc.status.INVALID_ARGUMENT, "Invalid order ID")
      );
    }

    let result;

    if (user.role === "admin") {
      result = await pool.query(
        `
        DELETE FROM orders
        WHERE id = $1
        RETURNING id, user_id, item, amount
        `,
        [orderId]
      );
    } else {
      result = await pool.query(
        `
        DELETE FROM orders
        WHERE id = $1
        AND user_id = $2
        RETURNING id, user_id, item, amount
        `,
        [orderId, user.id]
      );
    }

    if (result.rows.length === 0) {
      return callback(
        grpcError(grpc.status.NOT_FOUND, "Order not found or you do not own this order")
      );
    }

    callback(null, result.rows[0]);
  } catch (err) {
    callback(
      grpcError(grpc.status.INTERNAL, "Internal server error")
    );
  }
}

export async function DeleteUser(call, callback) {
  try {
    const user = await getAuthenticatedUser(call);

    if (!user) {
      return callback(
        grpcError(grpc.status.UNAUTHENTICATED, "Authentication required")
      );
    }

    const targetId = Number(call.request.id);
    if (!Number.isInteger(targetId) || targetId <= 0) {
      return callback(
        grpcError(grpc.status.INVALID_ARGUMENT, "Invalid user ID")
      );
    }

    // Security: Verify authorization BEFORE querying target user existence
    if (user.role !== "admin" && targetId !== user.id) {
      return callback(
        grpcError(grpc.status.PERMISSION_DENIED, "Unauthorized")
      );
    }

    const targetUser = await pool.query(
      `
      SELECT id, email, role
      FROM users
      WHERE id = $1
      `,
      [targetId]
    );

    if (targetUser.rows.length === 0) {
      return callback(
        grpcError(grpc.status.NOT_FOUND, "User not found")
      );
    }

    const target = targetUser.rows[0];

    if (target.role === "admin") {
      return callback(
        grpcError(grpc.status.PERMISSION_DENIED, "Admin accounts cannot be deleted")
      );
    }

    const result = await pool.query(
      `
      DELETE FROM users
      WHERE id = $1
      RETURNING id, email, role
      `,
      [targetId]
    );

    callback(null, result.rows[0]);
  } catch (err) {
    callback(
      grpcError(grpc.status.INTERNAL, "Internal server error")
    );
  }
}