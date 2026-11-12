CREATE TABLE vault_identity (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  key_version INTEGER NOT NULL CHECK(key_version > 0),
  nonce BLOB NOT NULL CHECK(length(nonce) = 12),
  ciphertext BLOB NOT NULL
);
