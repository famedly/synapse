-- JSONB and the operators we use are compatible with both Postgres 9.5+ and SQLite 3.38.0+
-- The UNIQUE constraint helps not only to insure there are never more than one grouping
-- of restrictions for a given server_name/media_id combo, but also act as an index
CREATE TABLE media_attachments (
    server_name TEXT NOT NULL,
    media_id TEXT NOT NULL,
    restrictions_json JSONB NOT NULL,
    UNIQUE (server_name, media_id)
);
