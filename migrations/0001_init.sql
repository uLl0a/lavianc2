CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

CREATE TABLE operators (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      CITEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'operator' CHECK (role IN ('admin','operator','viewer')),
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ
);

CREATE TABLE listeners (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL UNIQUE,
    type       TEXT NOT NULL CHECK (type IN ('https','dns','mtls','http')),
    bind_addr  TEXT NOT NULL,
    port       INT  NOT NULL CHECK (port > 0 AND port < 65536),
    domain     TEXT,
    tls_cert   BYTEA,
    tls_key    BYTEA,
    config     JSONB NOT NULL DEFAULT '{}'::jsonb,
    active     BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE implants (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_key    TEXT UNIQUE NOT NULL,
    hostname       TEXT,
    username       TEXT,
    os             TEXT,
    arch           TEXT,
    pid            INT,
    process_name   TEXT,
    internal_ip    TEXT,
    external_ip    TEXT,
    listener_id    UUID REFERENCES listeners(id) ON DELETE SET NULL,
    public_key     BYTEA NOT NULL,
    status         TEXT NOT NULL DEFAULT 'alive' CHECK (status IN ('alive','sleeping','dead','killed')),
    sleep_interval INT  NOT NULL DEFAULT 60 CHECK (sleep_interval > 0),
    jitter         INT  NOT NULL DEFAULT 10 CHECK (jitter >= 0 AND jitter <= 100),
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_check_in  TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_implants_status       ON implants(status);
CREATE INDEX idx_implants_listener     ON implants(listener_id);
CREATE INDEX idx_implants_last_checkin ON implants(last_check_in DESC);

CREATE TABLE tasks (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    implant_id     UUID NOT NULL REFERENCES implants(id) ON DELETE CASCADE,
    operator_id    UUID NOT NULL REFERENCES operators(id),
    command        TEXT NOT NULL,
    args           JSONB NOT NULL DEFAULT '[]'::jsonb,
    payload        BYTEA,
    status         TEXT NOT NULL DEFAULT 'pending' 
                   CHECK (status IN ('pending','sent','running','completed','failed')),
    output         BYTEA,
    error          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at  TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ
);
CREATE INDEX idx_tasks_implant_status ON tasks(implant_id, status);
CREATE INDEX idx_tasks_status_created ON tasks(status, created_at DESC);

CREATE TABLE events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    level       TEXT NOT NULL CHECK (level IN ('debug','info','warn','error')),
    category    TEXT NOT NULL,
    message     TEXT NOT NULL,
    operator_id UUID REFERENCES operators(id) ON DELETE SET NULL,
    implant_id  UUID REFERENCES implants(id) ON DELETE SET NULL,
    task_id     UUID REFERENCES tasks(id) ON DELETE SET NULL,
    listener_id UUID REFERENCES listeners(id) ON DELETE SET NULL,
    data        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_events_created_at ON events(created_at DESC);
CREATE INDEX idx_events_category   ON events(category);
CREATE INDEX idx_events_implant    ON events(implant_id);
CREATE INDEX idx_events_listener   ON events(listener_id);

-- Permite que el team server sobreviva a reinicios sin perder las
-- claves derivadas por ECDH para cada implante.
CREATE TABLE session_keys (
    implant_id    UUID PRIMARY KEY REFERENCES implants(id) ON DELETE CASCADE,
    c2_to_beacon  BYTEA NOT NULL,       -- clave AES-256-GCM C2 → implante
    beacon_to_c2  BYTEA NOT NULL,       -- clave AES-256-GCM implante → C2
    msg_count     BIGINT NOT NULL DEFAULT 0,
    rekey_every   BIGINT NOT NULL DEFAULT 1000,
    last_rekey_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE builds (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id  UUID REFERENCES operators(id) ON DELETE SET NULL,
    listener_id  UUID REFERENCES listeners(id) ON DELETE SET NULL,
    profile_name TEXT NOT NULL,
    target_os    TEXT NOT NULL,
    target_arch  TEXT NOT NULL,
    format       TEXT NOT NULL,
    listener_url TEXT NOT NULL,
    sleep_secs   INT  NOT NULL DEFAULT 60,
    jitter_perc  INT  NOT NULL DEFAULT 10,
    obfuscate    BOOLEAN NOT NULL DEFAULT false,
    compress     BOOLEAN NOT NULL DEFAULT false,
    output_path  TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL DEFAULT 0,
    duration_ms  BIGINT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_builds_operator   ON builds(operator_id);
CREATE INDEX idx_builds_created_at ON builds(created_at DESC);

CREATE TABLE artifacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    implant_id  UUID NOT NULL REFERENCES implants(id) ON DELETE CASCADE,
    task_id     UUID REFERENCES tasks(id) ON DELETE SET NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('file','process','registry','network','service','scheduled_task','other')),
    path        TEXT,                    -- ruta del archivo/clave registro/etc.
    details     JSONB NOT NULL DEFAULT '{}'::jsonb,
    cleanup     BOOLEAN NOT NULL DEFAULT false,  -- ¿se limpió al final?
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_artifacts_implant ON artifacts(implant_id);
CREATE INDEX idx_artifacts_kind    ON artifacts(kind);

CREATE TABLE credentials (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    implant_id  UUID REFERENCES implants(id) ON DELETE SET NULL,
    username    TEXT NOT NULL,
    domain      TEXT,
    kind        TEXT NOT NULL CHECK (kind IN ('plaintext','ntlm','sha1','aes256','kerberos','token','other')),
    secret      BYTEA,                    -- cifrado en reposo (idealmente)
    source      TEXT,                     -- "lsass", "sam", "dpapi", etc.
    validated   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_credentials_implant ON credentials(implant_id);
CREATE INDEX idx_credentials_kind    ON credentials(kind);