#!/usr/bin/env python3
"""Read-only evidence from a stopped disposable app's SQLite + WAL copy.

The caller must force-stop before collecting files. This is not an app endpoint
or a substitute account verifier. Admission is checked by the real native peer.
"""
import hashlib
import json
import pathlib
import sqlite3
import sys

root = pathlib.Path(sys.argv[1])
files = list(root.rglob('accounts/*.sqlite'))
assert len(files) == 1, f'expected one account container, got {files}'
db = sqlite3.connect(f'file:{files[0]}?mode=ro', uri=True)
db.row_factory = sqlite3.Row

def rows(sql):
    return [{k: (v.hex() if isinstance(v, bytes) else v) for k, v in dict(r).items()}
            for r in db.execute(sql)]

keys = db.execute('SELECT signing,control,receiving FROM account_device WHERE id=1').fetchone()
device = hashlib.blake2b(b'BaseHero device keys\0' + b''.join(keys), digest_size=32).hexdigest()
result = {
    'file': files[0].name,
    'device': device,
    'identity': rows('SELECT handle,signing,control,receiving,policy,kind FROM account_device'),
    'account': rows('SELECT anchor,head_position,head_hash,stopped FROM account_state'),
    'account_events': rows('SELECT id,bytes FROM account_events ORDER BY id'),
    'progress': rows('SELECT log_kind,log_id,position,head_hash,receipt,stopped_reason FROM log_progress'),
    'base_copies': rows('SELECT position,account_event FROM log_account_change ORDER BY position'),
    'pending': db.execute('SELECT COUNT(*) FROM pending_note_work').fetchone()[0],
    'updates': rows('SELECT u.id,u.request,u.delta, EXISTS(SELECT 1 FROM pending_note_work w WHERE w.update_id=u.id) AS pending, EXISTS(SELECT 1 FROM note_outbox o WHERE o.update_id=u.id) AS packaged, p.acked_position,p.outcome FROM note_updates u LEFT JOIN note_outbox_progress p ON p.update_id=u.id ORDER BY u.id'),
}
print(json.dumps(result))
