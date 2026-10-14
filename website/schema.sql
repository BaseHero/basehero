-- No IP addresses, tracking identifiers, or behavioural analytics.
CREATE TABLE IF NOT EXISTS subscribers (
  email TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'unsubscribed', 'bounced')),
  requested_at TEXT NOT NULL,
  consent_source TEXT NOT NULL,
  confirmed_at TEXT,
  stopped_at TEXT,
  confirmation_hash TEXT UNIQUE,
  confirmation_expires_at TEXT,
  last_sent_at TEXT
);
CREATE INDEX IF NOT EXISTS subscribers_status ON subscribers(status);
