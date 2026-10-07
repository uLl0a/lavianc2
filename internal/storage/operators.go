package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uLl0a/lavianc2/internal/models"
)

// OperatorRepo define las operaciones sobre la tabla operators.
type OperatorRepo interface {
	// Create inserta un nuevo operador.
	Create(ctx context.Context, op *models.Operator) error

	// Get obtiene un operador por su ID.
	Get(ctx context.Context, id uuid.UUID) (*models.Operator, error)

	// GetByUsername obtiene un operador por su nombre de usuario.
	// Devuelve (nil, nil) si no existe, para facilitar la lógica de login.
	GetByUsername(ctx context.Context, username string) (*models.Operator, error)

	// List devuelve todos los operadores ordenados por fecha de creación.
	List(ctx context.Context) ([]*models.Operator, error)

	// UpdateStatus cambia el estado de un operador (active/disabled).
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.OperatorStatus) error

	// UpdateLastSeen actualiza la marca de último acceso.
	UpdateLastSeen(ctx context.Context, id uuid.UUID) error

	// UpdatePassword cambia el hash de la contraseña.
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error

	// Delete elimina un operador.
	Delete(ctx context.Context, id uuid.UUID) error
}

// operatorRepo implementa OperatorRepo con pgxpool.
type operatorRepo struct {
	pool *pgxpool.Pool
}

func (r *operatorRepo) Create(ctx context.Context, op *models.Operator) error {
	if op.ID == uuid.Nil {
		op.ID = uuid.New()
	}
	if op.CreatedAt.IsZero() {
		op.CreatedAt = time.Now().UTC()
	}
	if op.Status == "" {
		op.Status = models.OperatorActive
	}
	if op.Role == "" {
		op.Role = "operator"
	}

	query := `
		INSERT INTO operators (id, username, password_hash, role, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.pool.Exec(ctx, query,
		op.ID,
		op.Username,
		op.PasswordHash,
		op.Role,
		op.Status,
		op.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("storage: create operator: %w", err)
	}
	return nil
}

func (r *operatorRepo) Get(ctx context.Context, id uuid.UUID) (*models.Operator, error) {
	query := `
		SELECT id, username, password_hash, role, status, created_at, last_seen_at
		FROM operators
		WHERE id = $1`

	return r.scanOne(ctx, query, id)
}

func (r *operatorRepo) GetByUsername(ctx context.Context, username string) (*models.Operator, error) {
	query := `
		SELECT id, username, password_hash, role, status, created_at, last_seen_at
		FROM operators
		WHERE username = $1`

	return r.scanOne(ctx, query, username)
}

func (r *operatorRepo) List(ctx context.Context) ([]*models.Operator, error) {
	query := `
		SELECT id, username, password_hash, role, status, created_at, last_seen_at
		FROM operators
		ORDER BY created_at ASC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("storage: list operators: %w", err)
	}
	defer rows.Close()

	var ops []*models.Operator
	for rows.Next() {
		op := &models.Operator{}
		if err := rows.Scan(
			&op.ID,
			&op.Username,
			&op.PasswordHash,
			&op.Role,
			&op.Status,
			&op.CreatedAt,
			&op.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("storage: scan operator: %w", err)
		}
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: rows error: %w", err)
	}
	return ops, nil
}

func (r *operatorRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status models.OperatorStatus) error {
	query := `UPDATE operators SET status = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("storage: update operator status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: operador %s no encontrado", id)
	}
	return nil
}

func (r *operatorRepo) UpdateLastSeen(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE operators SET last_seen_at = now() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("storage: update last_seen: %w", err)
	}
	return nil
}

func (r *operatorRepo) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	query := `UPDATE operators SET password_hash = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, passwordHash)
	if err != nil {
		return fmt.Errorf("storage: update password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: operador %s no encontrado", id)
	}
	return nil
}

func (r *operatorRepo) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM operators WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("storage: delete operator: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: operador %s no encontrado", id)
	}
	return nil
}

// scanOne ejecuta una query que devuelve una sola fila y la mapea a Operator.
// Devuelve (nil, nil) si no hay filas, para simplificar la lógica del caller.
func (r *operatorRepo) scanOne(ctx context.Context, query string, arg any) (*models.Operator, error) {
	op := &models.Operator{}
	err := r.pool.QueryRow(ctx, query, arg).Scan(
		&op.ID,
		&op.Username,
		&op.PasswordHash,
		&op.Role,
		&op.Status,
		&op.CreatedAt,
		&op.LastSeenAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: scan operator: %w", err)
	}
	return op, nil
}
