-- Añade el tipo 'quic' a la CHECK de listeners.
ALTER TABLE listeners DROP CONSTRAINT IF EXISTS listeners_type_check;
ALTER TABLE listeners ADD CONSTRAINT listeners_type_check
  CHECK (type IN ('https','dns','mtls','http','quic'));