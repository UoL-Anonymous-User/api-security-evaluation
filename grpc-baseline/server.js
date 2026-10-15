import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import * as appService from "./appService.js";

const packageDefinition = protoLoader.loadSync("./proto/app.proto", {
  keepCase: true,
});

const proto = grpc.loadPackageDefinition(packageDefinition).app;
const server = new grpc.Server();

server.addService(proto.AppService.service, appService);

server.bindAsync(
  "0.0.0.0:50051",
  grpc.ServerCredentials.createInsecure(),
  () => {
    console.log("🚀 Naive gRPC Server running on port 50051");
  }
);