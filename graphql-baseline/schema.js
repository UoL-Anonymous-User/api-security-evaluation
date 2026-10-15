import { pool } from './db.js';

export const typeDefs = `#graphql
  type User {
    id: ID!
    email: String!
    role: String!
  }

  type Order {
    id: ID!
    user_id: ID!
    item: String!
    amount: Float!
  }

  type AuthPayload {
    token: String
    user: User
  }

  type Query {
    users: [User]
    user(id: ID!): User
    orders: [Order]
    order(id: ID!): Order
  }

  type Mutation {
    register(email: String!, password: String!, role: String): User
    login(email: String!, password: String!): AuthPayload
    createOrder(user_id: ID!, item: String!, amount: Float!): Order
    deleteOrder(id: ID!): Order
    deleteUser(id: ID!): User
  }
`;

export const resolvers = {
  Query: {
    users: async () => {
      const result = await pool.query('SELECT id, email, role FROM users');
      return result.rows;
    },
    user: async (_, { id }) => {
      const result = await pool.query('SELECT id, email, role FROM users WHERE id = $1', [id]);
      return result.rows[0];
    },
    orders: async () => {
      const result = await pool.query('SELECT * FROM orders');
      return result.rows;
    },
    order: async (_, { id }) => {
      const result = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
      return result.rows[0];
    },
  },

  Mutation: {
    register: async (_, { email, password, role }) => {
      const userRole = role || 'user';
      const result = await pool.query(
        'INSERT INTO users (email, password, role) VALUES ($1, $2, $3) RETURNING id, email, role',
        [email, password, userRole]
      );
      return result.rows[0];
    },
    login: async (_, { email, password }) => {
      const result = await pool.query(
        'SELECT id, email, role FROM users WHERE email = $1 AND password = $2', 
        [email, password]
      );
      
      if (result.rows.length === 0) {
        throw new Error("Invalid credentials");
      }
      
      return { 
        token: "unsecured-dummy-token", 
        user: result.rows[0] 
      };
    },
    createOrder: async (_, { user_id, item, amount }) => {
      const result = await pool.query(
        'INSERT INTO orders (user_id, item, amount) VALUES ($1, $2, $3) RETURNING *',
        [user_id, item, amount]
      );
      return result.rows[0];
    },
    deleteOrder: async (_, { id }) => {
      const result = await pool.query('DELETE FROM orders WHERE id = $1 RETURNING *', [id]);
      return result.rows[0];
    },
    deleteUser: async (_, { id }) => {
      const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id, email, role', [id]);
      return result.rows[0];
    }
  }
};