import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import fs from "fs";

import * as appService from "./appService.js";

const packageDefinition = protoLoader.loadSync("./proto/app.proto", {
  keepCase: true,
});

const proto = grpc.loadPackageDefinition(packageDefinition).app;

// Security: Enforce strict message size and concurrent stream limits
const server = new grpc.Server({
  "grpc.max_receive_message_length": 64 * 1024, // 64 KB max request payload
  "grpc.max_send_message_length": 1024 * 1024,  // 1 MB max response payload
  "grpc.max_concurrent_streams": 100,           // Cap concurrent streams per connection
});

server.addService(proto.AppService.service, appService);

// Read the TLS certificate and private key
const cert = fs.readFileSync("./certs/server.crt");
const key = fs.readFileSync("./certs/server.key");

// Create SSL/TLS credentials
const credentials = grpc.ServerCredentials.createSsl(null, [
  {
    cert_chain: cert,
    private_key: key,
  },
]);

server.bindAsync(
  "0.0.0.0:50051",
  credentials,
  (err) => {
    if (err) {
      console.error("Failed to bind gRPC server:", err.message);
      process.exit(1);
    }
    console.log("🔒 Secure gRPC Server running on port 50051");
  }
);