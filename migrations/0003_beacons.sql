-- Migración 0003: Multi-Beacon Manager.
-- Idempotente: usa IF NOT EXISTS. También aplicada desde NewStore para
-- entornos donde el volumen Docker ya existe (docker-entrypoint-initdb.d
-- solo corre al crear el volumen por primera vez).

CREATE TABLE IF NOT EXISTS beacon_groups (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    profile    TEXT NOT NULL DEFAULT 'long-haul'
               CHECK (profile IN ('short-haul','long-haul')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beacons (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id      UUID REFERENCES beacon_groups(id) ON DELETE SET NULL,
    name          TEXT NOT NULL,
    profile       TEXT NOT NULL DEFAULT 'long-haul'
                  CHECK (profile IN ('short-haul','long-haul')),
    state         TEXT NOT NULL DEFAULT 'online'
                  CHECK (state IN ('online','degraded','offline','admin-stop','internal-err')),
    fail_streak   INT  NOT NULL DEFAULT 0,
    max_fails     INT  NOT NULL DEFAULT 3 CHECK (max_fails >= 1),
    last_check_in TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_beacons_group ON beacons(group_id);
CREATE INDEX IF NOT EXISTS idx_beacons_state ON beacons(state);

-- Registro auditable de eventos por beacon (check-ins, fallos, cambios).
CREATE TABLE IF NOT EXISTS beacon_events (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beacon_id  UUID NOT NULL REFERENCES beacons(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,   -- transport-lost|agent-unavailable|admin-stop|internal-error|recovered
    detail     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_beacon_events_beacon ON beacon_events(beacon_id);
CREATE INDEX IF NOT EXISTS idx_beacon_events_created ON beacon_events(created_at DESC);

-- Cargas dinámicas (BOF, .NET assembly, hVNC) despachadas a beacons.
CREATE TABLE IF NOT EXISTS payloads (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beacon_id  UUID NOT NULL REFERENCES beacons(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('bof','assembly','hvnc')),
    data       BYTEA NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending','sent','running','completed','failed')),
    error      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payloads_beacon ON payloads(beacon_id);

-- Ampliar el check constraint de listeners para aceptar el listener
-- WebSocket del módulo multi-beacon. DROP+ADD es idempotente (re-aplicar
-- la migración no falla si ya está ampliado).
ALTER TABLE listeners DROP CONSTRAINT IF EXISTS listeners_type_check;
ALTER TABLE listeners ADD CONSTRAINT listeners_type_check
    CHECK (type = ANY (ARRAY['https','dns','mtls','http','quic','websocket']::text[]));
