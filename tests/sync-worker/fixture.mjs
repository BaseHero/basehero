// Test-only local RPC/HTTP harness. Never bundle as a deployed entry point.
import { BaseLog } from '../../services/sync-worker/src/worker.mjs';

export class FixtureBase extends BaseLog {
  async provision(gate, bodies = []) {
    const sql = this.ctx.storage.sql;
    this.ctx.storage.transactionSync(() => {
      sql.exec(`CREATE TABLE gate(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        base TEXT NOT NULL,order_format INTEGER,opening TEXT,position INTEGER NOT NULL,hash TEXT NOT NULL,
        incarnation TEXT NOT NULL,sequence INTEGER NOT NULL,checker_key TEXT NOT NULL,
        last_approval TEXT,last_ack TEXT)`);
      sql.exec(`CREATE TABLE events(position INTEGER PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,
        event_digest TEXT NOT NULL UNIQUE,commitment TEXT NOT NULL,event TEXT NOT NULL)`);
      sql.exec(`CREATE TABLE bodies(commitment TEXT PRIMARY KEY,body TEXT NOT NULL)`);
      sql.exec('INSERT INTO gate VALUES(1,?,?,?,?,?,?,?,?,NULL,NULL)',gate.base,gate.order_format,gate.order,gate.position,
        gate.hash,gate.incarnation,gate.sequence,gate.checker_key);
      for (const body of bodies) {
        sql.exec('INSERT INTO bodies(commitment,body) VALUES(?,?)', body.commitment, body.body);
      }
    });
    await this.ctx.storage.sync();
    return { ok: true };
  }
  async inspect() {
    const sql = this.ctx.storage.sql;
    return {
      gate: sql.exec('SELECT base,order_format,opening,position,hash,incarnation,sequence,checker_key,last_approval,last_ack FROM gate').toArray()[0],
      rows: sql.exec('SELECT position,event_id,event_digest,commitment,event FROM events ORDER BY position').toArray(),
      bodies: sql.exec('SELECT commitment,body FROM bodies ORDER BY commitment').toArray(),
    };
  }
  async tamper(column, value) {
    if (!['event','commitment','event_id','event_digest'].includes(column)) throw new Error('bad column');
    this.ctx.storage.sql.exec(`UPDATE events SET ${column}=? WHERE position=1`, value);
    await this.ctx.storage.sync();
    return { ok: true };
  }
  async tamperBody(commitment, value) {
    this.ctx.storage.sql.exec('UPDATE bodies SET body=? WHERE commitment=?', value, commitment);
    await this.ctx.storage.sync();
    return { ok: true };
  }
  async rewindGate(gate) {
    this.ctx.storage.sql.exec(`UPDATE gate SET position=?,hash=?,opening=?,sequence=?,last_approval=?,last_ack=? WHERE singleton=1`,
      gate.position, gate.hash, gate.opening, gate.sequence, gate.last_approval, gate.last_ack);
    await this.ctx.storage.sync();
    return { ok: true };
  }
  async damageTail(mode) {
    if (mode === 'missing') this.ctx.storage.sql.exec('DELETE FROM events WHERE position=(SELECT MAX(position) FROM events)');
    else if (mode === 'corrupt') this.ctx.storage.sql.exec("UPDATE events SET commitment='00' WHERE position=(SELECT MAX(position) FROM events)");
    else throw new Error('bad tail mode');
    await this.ctx.storage.sync();
    return { ok: true };
  }
  async breakWrite() {
    this.ctx.storage.sql.exec(`CREATE TRIGGER fail_gate BEFORE UPDATE ON gate BEGIN SELECT RAISE(ABORT,'test failure'); END`);
    await this.ctx.storage.sync();
    return { ok: true };
  }
}
export default {
  async fetch(request, env) {
    try {
      const { action, gate, bodies, request: operation, time, column, value, mode } = await request.json();
      const stub = env.BASE.get(env.BASE.idFromName('fixture'));
      const result = action === 'provision' ? await stub.provision(gate, bodies)
        : action === 'consume' ? await stub.consume(operation, operation.binding, time)
        : action === 'inspect' ? await stub.inspect()
        : action === 'tamper' ? await stub.tamper(column, value)
        : action === 'tamperBody' ? await stub.tamperBody(column, value)
        : action === 'rewindGate' ? await stub.rewindGate(gate)
        : action === 'damageTail' ? await stub.damageTail(mode)
        : action === 'breakWrite' ? await stub.breakWrite()
        : { refusal: 'Unavailable' };
      return Response.json(result, { status: result.refusal ? 403 : 200 });
    } catch { return Response.json({ refusal: 'Unavailable' }, { status: 403 }); }
  },
};
