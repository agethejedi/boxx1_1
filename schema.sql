
-- D1 schema for RiskXLabs Box

CREATE TABLE IF NOT EXISTS admins (
  email TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  admin_email TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS boxes (
  id TEXT PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL,
  crypto_address TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  submitted_at TEXT,
  retrieved_at TEXT,
  created_by_admin_email TEXT NOT NULL,
  last_retrieved_by_admin_email TEXT
);

CREATE INDEX IF NOT EXISTS idx_boxes_created_by ON boxes(created_by_admin_email);
CREATE INDEX IF NOT EXISTS idx_boxes_expires_at ON boxes(expires_at);
CREATE INDEX IF NOT EXISTS idx_boxes_status ON boxes(status);
