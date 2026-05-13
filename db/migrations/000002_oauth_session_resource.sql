-- +goose Up
ALTER TABLE oauth_sessions ADD COLUMN resource TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE oauth_sessions DROP COLUMN resource;
