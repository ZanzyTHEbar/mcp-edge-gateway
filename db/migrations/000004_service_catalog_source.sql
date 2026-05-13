-- +goose Up
ALTER TABLE service_catalog ADD COLUMN source TEXT NOT NULL DEFAULT 'dynamic' CHECK(source IN ('builtin', 'admin_api', 'config', 'dynamic'));

-- +goose Down
ALTER TABLE service_catalog DROP COLUMN source;
