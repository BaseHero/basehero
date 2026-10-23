// Alert text is derived from the host's verified kind and names, never from
// server-supplied prose. All names are inserted as text nodes by callers.
import { formatDeadline } from './devices.js';

export function alertText(alert) {
  const subject = alert.subject_name ?? 'A device';
  const actor = alert.actor_name ?? 'another device';
  switch (alert.kind) {
    case 'device_added_by_kit': return 'Your account was opened on a new device with your password and recovery kit';
    case 'device_added_by_qr': return `${subject} was added`;
    case 'kit_used': return 'Your recovery kit was used';
    case 'removal_requested': return `Removal of ${subject} requested from ${actor}`;
    case 'removal_cancelled': return `Removal of ${subject} was cancelled`;
    case 'removal_effective': return `${subject} was removed`;
    case 'kit_changed': return `Password and recovery kit changed from ${actor}`;
    case 'refused_change': return 'BaseHero refused an invalid change to your account';
    case 'kit_not_changed': return 'Your recovery kit wasn’t changed. Your old kit still works.';
    default: return 'Security alert';
  }
}
export function renderAlerts(root, rows) {
  const heading = document.createElement('h2'); heading.textContent = 'Security alerts';
  const list = document.createElement('ul'); list.className = 'alert-list';
  for (const alert of [...rows].sort((a,b) => (b.time_ms ?? 0) - (a.time_ms ?? 0) || b.id - a.id)) {
    const row = document.createElement('li'); row.textContent = alertText(alert);
    if (alert.kind === 'removal_requested' && alert.deadline_ms != null) {
      const time = document.createElement('small'); time.textContent = `Takes effect ${formatDeadline(alert.deadline_ms)}`; row.append(time);
    }
    list.append(row);
  }
  root.replaceChildren(heading,list);
}
