-- Modified for Railway owner-password authentication.
--
-- Refuse to drop the owner credential / bootstrap marker. Dropping it would
-- permanently lock the owner out of password sign-in (the server never
-- recreates a credential on a non-empty database), and dropping an
-- existing_data marker would discard the record that this database was closed
-- to owner bootstrap.
DO $$
BEGIN
    IF to_regclass('owner_bootstrap') IS NOT NULL AND EXISTS (SELECT 1 FROM owner_bootstrap) THEN
        RAISE EXCEPTION 'refusing to roll back 535_owner_password_auth: owner_bootstrap holds the owner credential or bootstrap marker; rolling back would permanently disable owner password sign-in. Keep this migration applied, or back up and delete the owner_bootstrap row first if you intend to remove owner-password authentication.';
    END IF;
END $$;

DROP TABLE IF EXISTS owner_password_login_attempt;
DROP TABLE IF EXISTS owner_bootstrap;
