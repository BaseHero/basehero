// Test-only peer for the desktop presence WebDriver run: the production host
// and device operations a second device uses, with a labelled software store
// and synthetic attestation. Never an app; the local stack is the service.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { appendFileSync, mkdirSync } from "node:fs";
import { once } from "node:events";
import path from "node:path";

export async function startPeer({ root, endpoint, bin }) {
  const dir = path.join(root, "peer");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const peer = spawn(bin, [dir, endpoint, "plain"], { stdio: ["pipe", "pipe", "pipe"] });
  const exited = once(peer, "exit");
  peer.stderr.on("data", data => appendFileSync(path.join(root, "peer-stderr.log"), data));
  let sequence = 0;
  const pending = new Map();
  const ready = new Promise(resolve => {
    createInterface({ input: peer.stdout }).on("line", line => {
      const value = JSON.parse(line);
      const logged = structuredClone(value);
      if (logged.ok?.qr) logged.ok.qr = "[omitted]";
      if (logged.ok?.svg) logged.ok.svg = "[omitted]";
      appendFileSync(path.join(root, "peer-replies.jsonl"), JSON.stringify(logged) + "\n");
      if (value.event === "ready") resolve(value);
      if (value.reply) {
        const waiter = pending.get(value.reply);
        pending.delete(value.reply);
        if (waiter) {
          clearTimeout(waiter.timer);
          value.err ? waiter.reject(Error(value.err)) : waiter.resolve(value.ok);
        }
      }
    });
  });
  peer.on("exit", (code, signal) => {
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(Error(`peer exited ${code}/${signal}`));
    }
    pending.clear();
  });
  const call = (op, args = {}) => {
    const seq = ++sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(seq);
        reject(Error(`peer ${op} timed out`));
      }, 310_000);
      pending.set(seq, { resolve, reject, timer });
      peer.stdin.write(JSON.stringify({ seq, op, ...args }) + "\n");
    });
  };
  // A peer that dies before it is ready must not outlive this call; once the
  // peer object is returned, quit() owns its exit.
  const exitedEarly = exited.then(([code, signal]) => {
    throw Error(`peer exited before ready ${code}/${signal}`);
  });
  exitedEarly.catch(() => {});
  try {
    await Promise.race([ready, exitedEarly]);
  } catch (error) {
    peer.kill("SIGTERM");
    throw error;
  }
  return {
    call,
    async until(action, label, ms = 120_000) {
      let last;
      for (const end = Date.now() + ms; Date.now() < end; await new Promise(r => setTimeout(r, 250))) {
        last = await action();
        if (last) return last;
      }
      throw Error(`timeout: ${label}; ${JSON.stringify(last)}`);
    },
    async quit() {
      if (peer.exitCode === null && peer.signalCode === null) await call("quit");
      const [code, signal] = await exited;
      assert.equal(code, 0, `peer exit ${code}/${signal}`);
    },
  };
}
