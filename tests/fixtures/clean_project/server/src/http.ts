import { createServer } from "node:http";

createServer((_req, res) => res.end("ok")).listen(8787, "127.0.0.1");
