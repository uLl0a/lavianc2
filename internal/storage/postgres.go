package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
	return s, nil
}

func (s *Store) Close() {
	s.Pool.Close()
}
