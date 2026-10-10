package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uLl0a/lavianc2/internal/beacons"
)

// Store agrupa todos los repositorios.
type Store struct {
	Pool *pgxpool.Pool

	Operators   OperatorRepo
	Implants    ImplantRepo
	Tasks       TaskRepo
	Listeners   ListenerRepo
	Events      EventRepo
	SessionKeys SessionKeyRepo
	Beacons     BeaconRepo
}

// BeaconRepo es la interfaz de persistencia del Multi-Beacon Manager.
type BeaconRepo interface {
	SaveGroup(ctx context.Context, g *beacons.BeaconGroup) error
	GetGroup(ctx context.Context, id uuid.UUID) (*beacons.BeaconGroup, error)
	ListGroups(ctx context.Context) ([]*beacons.BeaconGroup, error)
	Save(ctx context.Context, b *beacons.Beacon) error
	Get(ctx context.Context, id uuid.UUID) (*beacons.Beacon, error)
	List(ctx context.Context) ([]*beacons.Beacon, error)
	SetState(ctx context.Context, id uuid.UUID, state beacons.HealthState, failStreak int) error
	SetProfile(ctx context.Context, id uuid.UUID, profile beacons.Profile) error
	RecordEvent(ctx context.Context, beaconID uuid.UUID, kind beacons.FailureKind, detail string) error
}

// NewStore crea el pool de conexiones y los repositorios.
func NewStore(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("storage: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("storage: ping: %w", err)
	}

	s := &Store{Pool: pool}
	s.Operators = &operatorRepo{pool: pool}
	s.Implants = &implantRepo{pool: pool}
	s.Tasks = &taskRepo{pool: pool}
	s.Listeners = &listenerRepo{pool: pool}
	s.Events = &eventRepo{pool: pool}
	s.SessionKeys = &sessionKeyRepo{pool: pool}
	s.Beacons = NewBeaconRepo(pool)

	// Aplicar migraciones idempotentes del Multi-Beacon Manager. Esto
	// cubre el caso en que el volumen Docker ya existía antes de que se
	// añadiera migrations/0003_beacons.sql a docker-entrypoint-initdb.d
	// (ese hook solo corre al crear el volumen la primera vez).
	if err := ensureBeaconTables(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("storage: aplicar migraciones de beacons: %w", err)
	}
	return s, nil
}

// beaconTablesDDL es el esquema idempotente de las tablas del manager.
const beaconTablesDDL = `
CREATE TABLE IF NOT EXISTS beacon_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'long-haul' CHECK (profile IN ('short-haul','long-haul')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS beacons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    implant_id UUID REFERENCES implants(id) ON DELETE SET NULL,
    group_id UUID REFERENCES beacon_groups(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'long-haul' CHECK (profile IN ('short-haul','long-haul')),
    state TEXT NOT NULL DEFAULT 'online' CHECK (state IN ('online','degraded','offline','admin-stop','internal-err')),
    fail_streak INT NOT NULL DEFAULT 0,
    max_fails INT NOT NULL DEFAULT 3 CHECK (max_fails >= 1),
    last_check_in TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_beacons_group ON beacons(group_id);
CREATE INDEX IF NOT EXISTS idx_beacons_state ON beacons(state);
CREATE INDEX IF NOT EXISTS idx_beacons_implant ON beacons(implant_id);
CREATE TABLE IF NOT EXISTS beacon_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beacon_id UUID NOT NULL REFERENCES beacons(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_beacon_events_beacon ON beacon_events(beacon_id);
CREATE TABLE IF NOT EXISTS payloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beacon_id UUID NOT NULL REFERENCES beacons(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('bof','assembly','hvnc')),
    data BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','running','completed','failed')),
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payloads_beacon ON payloads(beacon_id);
`

// ensureBeaconTables aplica el DDL idempotente del manager sentencia a
// sentencia (si una falla, las demás igual se intentan) y luego asegura la
// columna implant_id para tablas 'beacons' creadas antes de la adopción.
func ensureBeaconTables(ctx context.Context, pool *pgxpool.Pool) error {
	for _, stmt := range strings.Split(beaconTablesDDL, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := pool.Exec(ctx, stmt); err != nil {
			// Log pero no abortar: el resto de sentencias son independientes.
			fmt.Printf("storage: migración beacons (aviso): %v\n", err)
		}
	}
	const addCol = `ALTER TABLE beacons ADD COLUMN IF NOT EXISTS implant_id UUID REFERENCES implants(id) ON DELETE SET NULL`
	_, err := pool.Exec(ctx, addCol)
	return err
}

func (s *Store) Close() {
	s.Pool.Close()
}
