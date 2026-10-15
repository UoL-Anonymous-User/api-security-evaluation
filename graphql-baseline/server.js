import express from 'express';
import cors from 'cors';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@as-integrations/express4';
import { typeDefs, resolvers } from './schema.js';

const app = express();

// Standard middleware
app.use(cors());
app.use(express.json());

// Initialize Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
});

await server.start();

// Mount GraphQL on the Express server without an authentication context
app.use('/graphql', expressMiddleware(server));

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`🚀 Unsecured GraphQL API running at http://localhost:${PORT}/graphql`);
});