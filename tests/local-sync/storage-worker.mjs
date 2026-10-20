// Test-only internal access to a stopped local stack's log storage. Keeps the
// production class name so Miniflare opens the same namespace files. The
// sweep is the production reclaim (`alarm`) under a later test clock.
import { LogObject as ProductionLog } from '../../services/sync-worker/src/log.mjs';

const hex = b => Array.from(new Uint8Array(b), v => v.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../g) ?? [], h => parseInt(h, 16));

export class LogObject extends ProductionLog {
  offset = 0;
  constructor(ctx, env) {
    super(ctx, env, { now: () => Date.now() + this.offset });
  }
  async inspect() {
    const sql = this.ctx.storage.sql;
    return {
      events: sql.exec('SELECT position,event_id,digest,control,commitment FROM events ORDER BY position').toArray()
        .map(r => ({ ...r, commitment: hex(r.commitment) })),
      bodies: sql.exec('SELECT commitment,state,len,since_ms FROM bodies ORDER BY commitment').toArray(),
      meta: Object.fromEntries(sql.exec('SELECT key,value FROM meta').toArray().map(r => [r.key, r.value])),
      alarm: await this.ctx.storage.getAlarm(),
    };
  }
  async sweepAfter(offset) {
    this.offset = offset;
    await this.alarm();
    return this.inspect();
  }
  async rewriteHead(hash) {
    const sql = this.ctx.storage.sql;
    const head = JSON.parse(sql.exec("SELECT value FROM meta WHERE key='head'").one().value);
    sql.exec("UPDATE meta SET value=? WHERE key='head'", JSON.stringify({ position: head.position, hash }));
    await this.ctx.storage.sync();
    return { before: head, after: { position: head.position, hash } };
  }
}

export default {
  async fetch(request, env) {
    const { op, log, args = [] } = await request.json();
    if (op === 'r2-get' || op === 'r2-put' || op === 'r2-delete') {
      const key = `b/${log}/${args[0]}`;
      if (op === 'r2-delete') {
        await env.BODIES.delete(key);
        return Response.json({ ok: true });
      }
      if (op === 'r2-put') {
        await env.BODIES.put(key, unhex(args[1]));
        return Response.json({ ok: true });
      }
      const object = await env.BODIES.get(key);
      return Response.json({ bytes: object ? hex(await object.arrayBuffer()) : null });
    }
    const stub = env.LOG.get(env.LOG.idFromName(log));
    return Response.json(await stub[op](...args));
  },
};
