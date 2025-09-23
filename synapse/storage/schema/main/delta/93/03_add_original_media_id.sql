ALTER TABLE local_media_repository
ADD COLUMN original_media_id text;

ALTER TABLE remote_media_cache
ADD COLUMN original_media_id text;
