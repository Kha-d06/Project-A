// Relays newline-delimited JSON between stdin/stdout and the Qalaa service
// (Unix socket or Windows named pipe), so the Python runner works the same on
// every OS. Usage: node ipc-bridge.mjs <endpoint>
import { createConnection } from "node:net";

const socket = createConnection(process.argv[2]);
socket.setEncoding("utf8");
socket.on("data", (chunk) => process.stdout.write(chunk));
socket.on("error", (error) => {
  process.stderr.write(`bridge: ${error.message}\n`);
  process.exit(2);
});
socket.on("close", () => process.exit(0));
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => socket.write(chunk));
process.stdin.on("end", () => socket.end());
