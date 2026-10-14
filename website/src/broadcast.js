import { mailingFooter } from './mail-footer.js';

// Invoke only from an authorised campaign job after checking the campaign, audience
// and spending. There is deliberately no public HTTP endpoint for sending campaigns.
export async function sendBroadcast(env, { subject, text }, fetcher = fetch) {
  if (!env.DB || !env.LETTERMINT_PROJECT_TOKEN || !env.MAIL_FROM || !env.LETTERMINT_BROADCAST_ROUTE) throw Error('Broadcast not configured');
  if (!subject || !text) throw Error('Campaign content required');
  let sent = 0;
  let cursor = '';
  while (true) {
    const { results } = await env.DB.prepare("SELECT email FROM subscribers WHERE status='confirmed' AND email>? ORDER BY email LIMIT 100").bind(cursor).all();
    if (!results.length) break;
    for (const { email } of results) {
      cursor = email;
      // Recheck immediately before sending; the provider also suppresses hosted
      // unsubscribes, complaints and hard bounces even if a webhook is delayed.
      const row = await env.DB.prepare('SELECT status FROM subscribers WHERE email=?').bind(email).first();
      if (row?.status !== 'confirmed') continue;
      const response = await fetcher('https://api.lettermint.co/v1/send', {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-lettermint-token': env.LETTERMINT_PROJECT_TOKEN },
        body: JSON.stringify({ route: env.LETTERMINT_BROADCAST_ROUTE, from: env.MAIL_FROM, to: [email], subject, text: `${text}${mailingFooter}`,
          settings: { track_opens: false, track_clicks: false } })
      });
      if (!response.ok) throw Error(`Campaign halted on delivery error (${response.status})`);
      sent++;
    }
  }
  return sent;
}
