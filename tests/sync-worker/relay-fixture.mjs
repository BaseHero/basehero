// Test-only harness for the pairing relay: the real edge routes with a settable
// relay clock. Never bundle as a deployed entry point.
import edge from '../../services/sync-worker/src/edge.mjs';
import { PairingRelay } from '../../services/sync-worker/src/relay.mjs';

export { LogObject } from '../../services/sync-worker/src/log.mjs';

export class FixtureRelay extends PairingRelay {
  clock = 0;
  constructor(ctx, env) {
    super(ctx, env, { now: () => this.clock });
  }
  async control(settings) {
    Object.assign(this, settings);
    return { ok: true };
  }
  async inspect() {
    return [...(await this.ctx.storage.list()).keys()];
  }
  async sweep() {
    await this.alarm();
    return { ok: true };
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname !== '/control') return edge.fetch(request, env, ctx);
    const stub = env.RELAY.get(env.RELAY.idFromName(url.searchParams.get('name')));
    const { action, args = [] } = await request.json();
    if (!['control', 'inspect', 'sweep'].includes(action)) return new Response(null, { status: 400 });
    return Response.json(await stub[action](...args));
  },
};
