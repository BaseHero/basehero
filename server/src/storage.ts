import type { Env } from './http';

/** Sum all R2 object sizes under a base prefix, across every listing page. */
export async function listedBytes(env: Env, prefix: string): Promise<number> {
  let total = 0;
  let cursor: string | undefined;
  do {
    const page = await env.FILES.list({ prefix, cursor });
    for (const object of page.objects) total += object.size;
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return total;
}
