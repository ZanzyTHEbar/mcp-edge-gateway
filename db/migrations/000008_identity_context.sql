-- +goose Up
ALTER TABLE subjects ADD COLUMN account_binding_id TEXT;
ALTER TABLE subjects ADD COLUMN account_binding_claim TEXT;
ALTER TABLE service_catalog ADD COLUMN identity_context TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(identity_context));

-- +goose Down
ALTER TABLE service_catalog DROP COLUMN identity_context;
ALTER TABLE subjects DROP COLUMN account_binding_claim;
ALTER TABLE subjects DROP COLUMN account_binding_id;
