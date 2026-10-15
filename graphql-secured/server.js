import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { ApolloServer } from "@apollo/server";
import { expressMiddleware } from "@as-integrations/express5";
import { ApolloServerPluginDrainHttpServer } from "@apollo/server/plugin/drainHttpServer";
import { GraphQLError } from "graphql";
import http from "http";
import jwt from "jsonwebtoken";
import pool from "./db.js";

import typeDefs from "./schema/typeDefs.js";
import resolvers from "./schema/resolvers.js";

// Security Control (API2:2023 & API8:2023): Ensure strong JWT_SECRET on startup
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error(
    "CRITICAL: JWT_SECRET environment variable must be defined and at least 32 characters long."
  );
}

const app = express();
const httpServer = http.createServer(app);

// Security Control (API8:2023): Set secure HTTP response headers
app.use(
  helmet({
    contentSecurityPolicy: process.env.NODE_ENV === "production" ? undefined : false,
  })
);

// Security Control (API8:2023): Restrict cross-origin requests
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(",")
      : ["http://localhost:3000"],
    methods: ["POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Security Control (API2:2023 & API4:2023): HTTP rate limiting
const graphqlRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    errors: [
      {
        message: "Too many requests, please try again later.",
        extensions: { code: "TOO_MANY_REQUESTS" },
      },
    ],
  },
});

// Security Control (API4:2023): Block GraphQL alias flooding & excessive nesting depth
function createQueryLimitsPlugin({ maxAliases = 5, maxDepth = 5 } = {}) {
  function countAliasesAndDepth(selectionSet, currentDepth = 1) {
    if (!selectionSet || !selectionSet.selections) {
      return { aliases: 0, depth: currentDepth };
    }

    if (currentDepth > maxDepth) {
      throw new GraphQLError(`Query exceeds maximum allowed depth of ${maxDepth}.`, {
        extensions: { code: "BAD_USER_INPUT" },
      });
    }

    let totalAliases = 0;
    let deepest = currentDepth;

    for (const selection of selectionSet.selections) {
      if (selection.alias) {
        totalAliases += 1;
      }
      if (selection.selectionSet) {
        const childStats = countAliasesAndDepth(
          selection.selectionSet,
          currentDepth + 1
        );
        totalAliases += childStats.aliases;
        if (childStats.depth > deepest) {
          deepest = childStats.depth;
        }
      }
    }

    return { aliases: totalAliases, depth: deepest };
  }

  return {
    async requestDidStart() {
      return {
        async didResolveOperation({ document }) {
          let totalAliases = 0;

          for (const definition of document.definitions) {
            if (definition.kind === "OperationDefinition" && definition.selectionSet) {
              const stats = countAliasesAndDepth(definition.selectionSet, 1);
              totalAliases += stats.aliases;
            }
          }

          if (totalAliases > maxAliases) {
            throw new GraphQLError(
              `Query exceeds maximum allowed aliases (${maxAliases}).`,
              { extensions: { code: "BAD_USER_INPUT" } }
            );
          }
        },
      };
    },
  };
}

const server = new ApolloServer({
  typeDefs,
  resolvers,
  // Security Control (API8:2023 & API9:2023): Disable introspection in production
  introspection: process.env.NODE_ENV !== "production",
  plugins: [
    ApolloServerPluginDrainHttpServer({ httpServer }),
    createQueryLimitsPlugin({ maxAliases: 5, maxDepth: 5 }),
  ],
  // Security Control (API8:2023): Explicitly prevent stack trace leakage
  includeStacktraceInErrorResponses: false,
  formatError: (formattedError) => {
    const allowedErrorCodes = [
      "BAD_USER_INPUT",
      "UNAUTHENTICATED",
      "FORBIDDEN",
      "GRAPHQL_VALIDATION_FAILED",
      "PERSISTED_QUERY_NOT_FOUND",
    ];

    // Mask unexpected internal/database errors completely
    if (!allowedErrorCodes.includes(formattedError.extensions?.code)) {
      return {
        message: "Internal server error",
        extensions: { code: "INTERNAL_SERVER_ERROR" },
      };
    }

    return {
      message: formattedError.message,
      extensions: { code: formattedError.extensions?.code },
    };
  },
});

await server.start();

app.use(
  "/graphql",
  graphqlRateLimiter,
  // Security Control (API4:2023): Restrict request body size to 10KB
  express.json({ limit: "10kb" }),
  expressMiddleware(server, {
    context: async ({ req }) => {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return { user: null };
      }

      const token = authHeader.split(" ")[1];
      if (!token) {
        return { user: null };
      }

      try {
        // Security Control (API2:2023): Pin expected JWT signing algorithm
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
          algorithms: ["HS256"],
        });

        // Security Control (API2:2023 & API5:2023): Verify user still exists and role is current
        const result = await pool.query(
          "SELECT id, email, role FROM users WHERE id = $1",
          [decoded.id]
        );

        if (result.rows.length === 0) {
          return { user: null };
        }

        return { user: result.rows[0] };
      } catch {
        return { user: null };
      }
    },
  })
);

const PORT = process.env.PORT || 4000;

await new Promise((resolve) =>
  httpServer.listen({ port: PORT }, resolve)
);

console.log(
  `🚀 GraphQL running at http://localhost:${PORT}/graphql`
);