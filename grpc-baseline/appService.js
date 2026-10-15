import pool from "./db.js";

// A naive developer hardcodes the role to 'user' and stores passwords in plaintext.
export async function Register(call, callback) {
  const { email, password } = call.request;
  try {
    const result = await pool.query(
      `INSERT INTO users (email, password, role) VALUES ($1, $2, 'user') RETURNING id, email, role`,
      [email, password]
    );
    callback(null, result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return callback(new Error("Email already registered"));
    }
    callback(new Error("Registration failed"));
  }
}

// Compares plaintext passwords and returns the user object directly.
export async function Login(call, callback) {
  const { email, password } = call.request;
  try {
    const result = await pool.query(
      `SELECT id, email, role FROM users WHERE email = $1 AND password = $2`,
      [email, password]
    );
    if (result.rows.length === 0) {
      return callback(new Error("Invalid credentials"));
    }
    callback(null, result.rows[0]);
  } catch (err) {
    callback(err);
  }
}

// Returns all users directly from the database without checking permissions.
export async function GetUsers(call, callback) {
  try {
    const result = await pool.query(`SELECT id, email, role FROM users`);
    callback(null, { users: result.rows });
  } catch (err) {
    callback(err);
  }
}

// Relies completely on the client providing an ID (BOLA vulnerability).
export async function GetUser(call, callback) {
  try {
    const result = await pool.query(
      `SELECT id, email, role FROM users WHERE id = $1`,
      [call.request.id]
    );
    callback(null, result.rows[0]);
  } catch (err) {
    callback(err);
  }
}

// Returns all orders in the database.
export async function GetOrders(call, callback) {
  try {
    const result = await pool.query(`SELECT * FROM orders`);
    callback(null, { orders: result.rows });
  } catch (err) {
    callback(err);
  }
}

export async function GetOrder(call, callback) {
  try {
    const result = await pool.query(
      `SELECT * FROM orders WHERE id = $1`,
      [call.request.id]
    );
    callback(null, result.rows[0]);
  } catch (err) {
    callback(err);
  }
}

// Organically introduces IDOR because the developer relies on the client for the user_id.
export async function CreateOrder(call, callback) {
  const { user_id, item, amount } = call.request;
  try {
    const result = await pool.query(
      `INSERT INTO orders (user_id, item, amount) VALUES ($1, $2, $3) RETURNING *`,
      [user_id, item, amount]
    );
    callback(null, result.rows[0]);
  } catch (err) {
    callback(err);
  }
}

// Deletes any order based solely on the ID provided by the client.
export async function DeleteOrder(call, callback) {
  try {
    const result = await pool.query(
      `DELETE FROM orders WHERE id = $1 RETURNING *`,
      [call.request.id]
    );
    callback(null, result.rows[0]);
  } catch (err) {
    callback(err);
  }
}

// Deletes any user based solely on the ID provided by the client.
export async function DeleteUser(call, callback) {
  try {
    const result = await pool.query(
      `DELETE FROM users WHERE id = $1 RETURNING id, email, role`,
      [call.request.id]
    );
    callback(null, result.rows[0]);
  } catch (err) {
    callback(err);
  }
}