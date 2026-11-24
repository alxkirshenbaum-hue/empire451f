CREATE TABLE profile_issuance (
  id INTEGER PRIMARY KEY,
  event TEXT NOT NULL CHECK(event='PROFILE_ISSUED'),
  admin_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  issued_at TEXT NOT NULL
);
