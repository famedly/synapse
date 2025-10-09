ALTER TABLE local_media_repository_thumbnails
ADD COLUMN thumbnail_sha256 TEXT;
UNIQUE thumbnail_sha256;

ALTER TABLE remote_media_cache_thumbnails
ADD COLUMN thumbnail_sha256 TEXT;