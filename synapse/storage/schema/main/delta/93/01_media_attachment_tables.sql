
CREATE TABLE media_attachments_events (
    mxc_id TEXT PRIMARY KEY, -- implies NOT NULL and provides a UNIQUE index
    event_id TEXT NOT NULL,
);

CREATE INDEX media_attachments_event_idx ON media_attachments_events(event_id);

CREATE TABLE media_attachments_profiles (
    mxc_id TEXT PRIMARY KEY,
    profile_user_id TEXT NOT NULL,
);

CREATE INDEX media_attachments_profile_user_id_idx ON media_attachments_profiles(profile_user_id);
