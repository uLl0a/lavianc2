package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uLl0a/lavianc2/internal/models"
)

// ListenerRepo define las operaciones sobre la tabla listeners.
type ListenerRepo interface {
	// Create inserta un nuevo listener.
	Create(ctx context.Context, l *models.Listener) error

	// Get obtiene un listener por su UUID.
	Get(ctx context.Context, id uuid.UUID) (*models.Listener, error)

	// GetByName obtiene un listener por su nombre único.
	GetByName(ctx context.Context, name string) (*models.Listener, error)

	// List devuelve todos los listeners.
	List(ctx context.Context) ([]*models.Listener, error)

	// ListActive devuelve solo los listeners activos.
	ListActive(ctx context.Context) ([]*models.Listener, error)

	// UpdateConfig reemplaza el JSONB de config.
	UpdateConfig(ctx context.Context, id uuid.UUID, config map[string]any) error

	// UpdateTLS actualiza el certificado y la clave TLS del listener.
	UpdateTLS(ctx context.Context, id uuid.UUID, cert, key []byte) error

	// SetActive activa o desactiva el listener.
	SetActive(ctx context.Context, id uuid.UUID, active bool) error

	// Delete elimina un listener.
	Delete(ctx context.Context, id uuid.UUID) error
}

// listenerRepo implementa ListenerRepo con pgxpool.
type listenerRepo struct {
	pool *pgxpool.Pool
}

func (r *listenerRepo) Create(ctx context.Context, l *models.Listener) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	if l.Config == nil {
		l.Config = map[string]any{}
	}

	configJSON, err := json.Marshal(l.Config)
	if err != nil {
		return fmt.Errorf("storage: marshal listener config: %w", err)
	}

	query := `
		INSERT INTO listeners (
			id, name, type, bind_addr, port, domain,
			tls_cert, tls_key, config, active, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err = r.pool.Exec(ctx, query,
		l.ID,
		l.Name,
		l.Type,
		l.BindAddr,
		l.Port,
		l.Domain,
		l.TLSCert,
		l.TLSKey,
		configJSON,
		l.Active,
		l.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("storage: create listener: %w", err)
	}
	return nil
}

func (r *listenerRepo) Get(ctx context.Context, id uuid.UUID) (*models.Listener, error) {
	query := `
		SELECT id, name, type, bind_addr, port, domain,
		       tls_cert, tls_key, config, active, created_at
		FROM listeners
		WHERE id = $1`

	return r.scanOne(ctx, query, id)
}

func (r *listenerRepo) GetByName(ctx context.Context, name string) (*models.Listener, error) {
	query := `
		SELECT id, name, type, bind_addr, port, domain,
		       tls_cert, tls_key, config, active, created_at
		FROM listeners
		WHERE name = $1`

	return r.scanOne(ctx, query, name)
}

func (r *listenerRepo) List(ctx context.Context) ([]*models.Listener, error) {
	query := `
		SELECT id, name, type, bind_addr, port, domain,
		       tls_cert, tls_key, config, active, created_at
		FROM listeners
		ORDER BY created_at ASC`

	return r.scanMany(ctx, query)
}

func (r *listenerRepo) ListActive(ctx context.Context) ([]*models.Listener, error) {
	query := `
		SELECT id, name, type, bind_addr, port, domain,
		       tls_cert, tls_key, config, active, created_at
		FROM listeners
		WHERE active = true
		ORDER BY created_at ASC`

	return r.scanMany(ctx, query)
}

func (r *listenerRepo) UpdateConfig(ctx context.Context, id uuid.UUID, config map[string]any) error {
	if config == nil {
		config = map[string]any{}
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("storage: marshal listener config: %w", err)
	}
	query := `UPDATE listeners SET config = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, configJSON)
	if err != nil {
		return fmt.Errorf("storage: update listener config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: listener %s no encontrado", id)
	}
	return nil
}

func (r *listenerRepo) UpdateTLS(ctx context.Context, id uuid.UUID, cert, key []byte) error {
	query := `UPDATE listeners SET tls_cert = $2, tls_key = $3 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, cert, key)
	if err != nil {
		return fmt.Errorf("storage: update listener tls: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: listener %s no encontrado", id)
	}
	return nil
}

func (r *listenerRepo) SetActive(ctx context.Context, id uuid.UUID, active bool) error {
	query := `UPDATE listeners SET active = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, active)
	if err != nil {
		return fmt.Errorf("storage: set listener active: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: listener %s no encontrado", id)
	}
	return nil
}

func (r *listenerRepo) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM listeners WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("storage: delete listener: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: listener %s no encontrado", id)
	}
	return nil
}

func (r *listenerRepo) scanOne(ctx context.Context, query string, arg any) (*models.Listener, error) {
	l := &models.Listener{}
	var configJSON []byte

	err := r.pool.QueryRow(ctx, query, arg).Scan(
		&l.ID,
		&l.Name,
		&l.Type,
		&l.BindAddr,
		&l.Port,
		&l.Domain,
		&l.TLSCert,
		&l.TLSKey,
		&configJSON,
		&l.Active,
		&l.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: scan listener: %w", err)
	}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &l.Config); err != nil {
			return nil, fmt.Errorf("storage: unmarshal listener config: %w", err)
		}
	}
	return l, nil
}

func (r *listenerRepo) scanMany(ctx context.Context, query string, args ...any) ([]*models.Listener, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: query listeners: %w", err)
	}
	defer rows.Close()

	var listeners []*models.Listener
	for rows.Next() {
		l := &models.Listener{}
		var configJSON []byte

		if err := rows.Scan(
			&l.ID,
			&l.Name,
			&l.Type,
			&l.BindAddr,
			&l.Port,
			&l.Domain,
			&l.TLSCert,
			&l.TLSKey,
			&configJSON,
			&l.Active,
			&l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("storage: scan listener: %w", err)
		}
		if len(configJSON) > 0 {
			_ = json.Unmarshal(configJSON, &l.Config)
		}
		listeners = append(listeners, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: rows error: %w", err)
	}
	return listeners, nil
}
