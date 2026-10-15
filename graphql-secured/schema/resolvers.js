import pool from "../db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { GraphQLError } from "graphql";
import validator from "validator";

const BCRYPT_ROUNDS = 12;
// Precomputed bcrypt hash (cost=12) used to mitigate timing-based user enumeration on login
const DUMMY_PASSWORD_HASH =
  "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4oL2.8H/SO";

// Helper to validate database IDs
function isValidId(id) {
  return validator.isInt(String(id), { min: 1 });
}

const resolvers = {
  Query: {
    users: async (_, __, { user }) => {
      // Security Control (API5:2023): Strict admin function-level check
      if (!user || user.role !== "admin") {
        throw new GraphQLError("Unauthorized", {
          extensions: { code: "FORBIDDEN" },
        });
      }

      // Security Control (API4:2023): Bound result set size with LIMIT
      const result = await pool.query(
        "SELECT id, email, role FROM users ORDER BY id ASC LIMIT 100"
      );

      return result.rows;
    },

    user: async (_, __, { user }) => {
      if (!user) {
        throw new GraphQLError("Authentication required", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      const result = await pool.query(
        "SELECT id, email, role FROM users WHERE id = $1",
        [user.id]
      );

      return result.rows[0] || null;
    },

    orders: async (_, __, { user }) => {
      if (!user) {
        throw new GraphQLError("Authentication required", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      // Security Control (API3:2023 & API4:2023): Explicit column selection + LIMIT
      if (user.role === "admin") {
        const result = await pool.query(
          "SELECT id, user_id, item, amount FROM orders ORDER BY id DESC LIMIT 100"
        );
        return result.rows;
      }

      const result = await pool.query(
        "SELECT id, user_id, item, amount FROM orders WHERE user_id = $1 ORDER BY id DESC LIMIT 100",
        [user.id]
      );

      return result.rows;
    },

    order: async (_, { id }, { user }) => {
      if (!user) {
        throw new GraphQLError("Authentication required", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      if (!isValidId(id)) {
        throw new GraphQLError("Invalid order ID", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      if (user.role === "admin") {
        const result = await pool.query(
          "SELECT id, user_id, item, amount FROM orders WHERE id = $1",
          [id]
        );
        return result.rows[0] || null;
      }

      // Security Control (API1:2023): Enforce object ownership in SQL query
      const result = await pool.query(
        `SELECT id, user_id, item, amount
         FROM orders
         WHERE id = $1
         AND user_id = $2`,
        [id, user.id]
      );

      return result.rows[0] || null;
    },
  },

  Mutation: {
    register: async (_, { email, password }) => {
      // Security Control: Strict email format & length validation
      if (
        typeof email !== "string" ||
        email.length > 254 ||
        !validator.isEmail(email)
      ) {
        throw new GraphQLError("Invalid email format", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      // Security Control (API2:2023 & API4:2023): Enforce password complexity and 72-byte bcrypt limit
      if (
        typeof password !== "string" ||
        password.length < 8 ||
        Buffer.byteLength(password, "utf8") > 72
      ) {
        throw new GraphQLError(
          "Password must be between 8 and 72 characters long",
          { extensions: { code: "BAD_USER_INPUT" } }
        );
      }

      const sanitizedEmail = validator.normalizeEmail(email);
      if (!sanitizedEmail) {
        throw new GraphQLError("Invalid email format", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const result = await pool.query(
          `INSERT INTO users (email, password, role)
           VALUES ($1, $2, 'user')
           RETURNING id, email, role`,
          [sanitizedEmail, hashedPassword]
        );

        return result.rows[0];
      } catch (err) {
        if (err.code === "23505") {
          throw new GraphQLError("Registration could not be completed", {
            extensions: { code: "BAD_USER_INPUT" },
          });
        }

        throw new GraphQLError("Registration failed", {
          extensions: { code: "INTERNAL_SERVER_ERROR" },
        });
      }
    },

    login: async (_, { email, password }) => {
      // Reject oversized inputs before running bcrypt to prevent CPU DoS (API4:2023)
      if (
        typeof email !== "string" ||
        typeof password !== "string" ||
        email.length > 254 ||
        Buffer.byteLength(password, "utf8") > 72
      ) {
        throw new GraphQLError("Invalid credentials", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      const sanitizedEmail = validator.normalizeEmail(email) || email.trim().toLowerCase();

      const result = await pool.query(
        "SELECT id, email, password, role FROM users WHERE email = $1",
        [sanitizedEmail]
      );

      const user = result.rows[0];

      // Security Control (API2:2023): Always perform bcrypt comparison to prevent timing attacks
      const targetHash = user ? user.password : DUMMY_PASSWORD_HASH;
      const validPassword = await bcrypt.compare(password, targetHash);

      if (!user || !validPassword) {
        throw new GraphQLError("Invalid credentials", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      // Security Control (API2:2023): Explicitly specify signing algorithm
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

      return {
        token,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
        },
      };
    },

    deleteUser: async (_, { id }, { user }) => {
      if (!user) {
        throw new GraphQLError("Authentication required", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      if (!isValidId(id)) {
        throw new GraphQLError("Invalid user ID", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      // Security Control (API1:2023): Verify ownership/role BEFORE querying target user in DB
      const isSelf = Number(id) === Number(user.id);
      const isAdmin = user.role === "admin";

      if (!isAdmin && !isSelf) {
        throw new GraphQLError("Unauthorized", {
          extensions: { code: "FORBIDDEN" },
        });
      }

      // Prevent deletion of admin accounts at the query level
      const result = await pool.query(
        `DELETE FROM users
         WHERE id = $1
         AND role != 'admin'
         RETURNING id, email, role`,
        [id]
      );

      if (result.rows.length === 0) {
        throw new GraphQLError(
          "User could not be deleted or does not exist",
          { extensions: { code: "FORBIDDEN" } }
        );
      }

      return result.rows[0];
    },

    createOrder: async (_, { item, amount }, { user }) => {
      if (!user) {
        throw new GraphQLError("Authentication required", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      // Security Control (API6:2023): Validate item length and content
      if (typeof item !== "string") {
        throw new GraphQLError("Invalid item name", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      const trimmedItem = item.trim();
      if (trimmedItem.length < 1 || trimmedItem.length > 255) {
        throw new GraphQLError("Item name must be between 1 and 255 characters", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      // Security Control (API6:2023): Prevent negative, zero, NaN, or extreme order amounts
      if (!Number.isFinite(amount) || amount <= 0 || amount > 1_000_000) {
        throw new GraphQLError(
          "Order amount must be a positive number up to 1,000,000",
          { extensions: { code: "BAD_USER_INPUT" } }
        );
      }

      const sanitizedItem = validator.escape(trimmedItem);

      const result = await pool.query(
        `INSERT INTO orders (user_id, item, amount)
         VALUES ($1, $2, $3)
         RETURNING id, user_id, item, amount`,
        [user.id, sanitizedItem, amount]
      );

      return result.rows[0];
    },

    deleteOrder: async (_, { id }, { user }) => {
      if (!user) {
        throw new GraphQLError("Authentication required", {
          extensions: { code: "UNAUTHENTICATED" },
        });
      }

      if (!isValidId(id)) {
        throw new GraphQLError("Invalid order ID", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      let result;

      if (user.role === "admin") {
        result = await pool.query(
          `DELETE FROM orders
           WHERE id = $1
           RETURNING id, user_id, item, amount`,
          [id]
        );
      } else {
        result = await pool.query(
          `DELETE FROM orders
           WHERE id = $1
           AND user_id = $2
           RETURNING id, user_id, item, amount`,
          [id, user.id]
        );
      }

      if (result.rows.length === 0) {
        throw new GraphQLError(
          "Order not found or you do not own this order",
          { extensions: { code: "FORBIDDEN" } }
        );
      }

      return result.rows[0];
    },
  },
};

export default resolvers;