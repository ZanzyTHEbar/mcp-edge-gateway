-- +goose Up
ALTER TABLE oauth_sessions ADD COLUMN issued_via TEXT NOT NULL DEFAULT 'oauth';
ALTER TABLE oauth_sessions ADD COLUMN operator_reason TEXT;

-- +goose Down
ALTER TABLE oauth_sessions DROP COLUMN operator_reason;
ALTER TABLE oauth_sessions DROP COLUMN issued_via;
