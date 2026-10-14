import cryptoModule from '../probe.wasm';
import { assertImports, createHost } from '../../../libs/crypto/worker-host.mjs';

// This is a local verifier fixture, not a hosted sync checker or account home.
export default {
  async fetch() {
    assertImports(WebAssembly.Module.imports(cryptoModule));
    const host = createHost();
    const instance = await WebAssembly.instantiate(cryptoModule, host.imports);
    host.bindMemory(instance.exports.memory);
    const code = instance.exports.check_crypto();
    return new Response(JSON.stringify({ code, entropyCalls: host.entropyCalls }), {
      status: code === 0 && host.entropyCalls > 0 ? 200 : 500,
    });
  },
};
