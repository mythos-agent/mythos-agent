import { parentPort } from "node:worker_threads";
import { PARSERS } from "./parsers.js";
import type { ParserId } from "./types.js";

// This module is loaded both as a worker entry point (parentPort set) and
// — harmlessly — when bundlers walk imports. The handler only registers
// when actually running inside a worker.
if (parentPort) {
  parentPort.on("message", (msg: { parserId: string; input: string }) => {
    // Deliberate test hook: lets the worker-pool timeout path be exercised
    // against a guaranteed hang without depending on a real ReDoS input.
    if (msg.parserId === "__hang__") {
      while (true) {
        /* intentional infinite loop — the pool terminates this worker */
      }
    }
    const parser = PARSERS[msg.parserId as ParserId];
    parentPort!.postMessage(
      parser ? parser(msg.input) : { error: `unknown parser: ${msg.parserId}` }
    );
  });
}
