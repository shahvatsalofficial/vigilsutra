// Preload used by the runtime offline test: any attempt to use the network, DNS or a subprocess
// is recorded to the file named by VS_NET_LOG and then refused.
import net from "node:net";
import dns from "node:dns";
import childProcess from "node:child_process";
import { appendFileSync } from "node:fs";

const log = (what) => {
  try {
    appendFileSync(process.env.VS_NET_LOG, what + "\n");
  } catch {
    /* ignore */
  }
};
const deny = (what) => () => {
  log(what);
  throw new Error(`blocked: ${what}`);
};

net.Socket.prototype.connect = deny("net.Socket.connect");
net.connect = deny("net.connect");
net.createConnection = deny("net.createConnection");
dns.lookup = deny("dns.lookup");
dns.resolve = deny("dns.resolve");
dns.promises.lookup = deny("dns.promises.lookup");
globalThis.fetch = deny("fetch");
for (const fn of ["spawn", "exec", "execFile", "fork", "spawnSync", "execSync", "execFileSync"]) childProcess[fn] = deny(`child_process.${fn}`);
