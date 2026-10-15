import gql from "graphql-tag";

const typeDefs = gql`
  type User {
    id: ID!
    email: String!
    role: String!
  }

  type Order {
    id: ID!
    user_id: Int!
    item: String!
    amount: Float!
  }

  type AuthResponse {
    token: String!
    user: User!
  }

  type Query {
    users: [User]
    user: User

    orders: [Order]
    order(id: ID!): Order
  }

  type Mutation {
    register(
      email: String!
      password: String!
    ): User

    login(
      email: String!
      password: String!
    ): AuthResponse

    createOrder(
      item: String!
      amount: Float!
    ): Order

    deleteOrder(
      id: ID!
    ): Order

    deleteUser(
      id: ID!
    ): User
  }
`;

export default typeDefs;