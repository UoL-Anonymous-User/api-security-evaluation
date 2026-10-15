# Experimental Evaluation of Security Mechanisms Across REST, GraphQL, and gRPC APIs
  

## **Overview**
This repository contains the complete source code, database schemas, and configuration files for the six experimental API implementations evaluated in this MSc dissertation:
1. **REST Baseline (Unsecured)** & **REST Hardened (Secured)** — Express.js (`localhost:3000`)
2. **GraphQL Baseline (Unsecured)** & **GraphQL Hardened (Secured)** — Apollo Server (`localhost:4000/graphql`)
3. **gRPC Baseline (Unsecured)** & **gRPC Hardened (Secured)** — `@grpc/grpc-js` & Protocol Buffers (`localhost:50051`)

## Prerequisites
* **Node.js** (v18+ LTS)
* **PostgreSQL** (v15+ running on `localhost:5432`) & **pgAdmin 4**
* **Testing Tools:** Postman, `cURL`, and `grpcurl`

## **Setup & Installation**
1. Install dependencies:
   npm install express @apollo/server graphql graphql-tag @grpc/grpc-js @grpc/proto-loader pg dotenv bcrypt jsonwebtoken validator helmet cors express-rate-limit

2. Initialize PostgreSQL Database (api_db):
   Run the SQL commands in database/schema.sql inside pgAdmin to create the users and orders tables with ON DELETE CASCADE.

3. Generate Self-Signed TLS Certificates (for Secured gRPC):
   mkdir certs
   openssl req -nodes -new -x509 -keyout certs/server.key -out certs/server.crt -days 365 -subj "/CN=localhost"


## **Running the APIs:**

REST Baseline: node rest-baseline/index.js

REST Secured: node rest-secured/index_2.js

GraphQL Baseline: node graphql-baseline/server.js

GraphQL Secured: node graphql-secured/server.js

gRPC Baseline: node grpc-baseline/server_3.js

gRPC Secured: node grpc-secured/server_4.js
