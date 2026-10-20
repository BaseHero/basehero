// Test-only internal SQL readback after the local stack's workerd has stopped.
// Keep the production class name so Miniflare opens the same namespace files.
import { LogObject as ProductionLog } from '../../services/sync-worker/src/log.mjs';
export class LogObject extends ProductionLog {
  async privateReadback() {
    const sql = this.ctx.storage.sql;
    const hex = b => Array.from(new Uint8Array(b), v => v.toString(16).padStart(2, '0')).join('');
    return {
      objects: sql.exec('SELECT prefix_digest,bundle_digest,bundle FROM private_home_objects').toArray()
        .map(r => ({ ...r, bundle: hex(r.bundle) })),
      positions: sql.exec('SELECT count(*) AS n FROM events').one().n,
      bodies: sql.exec('SELECT count(*) AS n FROM bodies').one().n,
    };
  }
}
export default {
  async fetch(request, env) {
    const log = new URL(request.url).searchParams.get('log');
    return Response.json(await env.LOG.get(env.LOG.idFromName(log)).privateReadback());
  },
};
