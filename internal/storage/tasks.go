package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uLl0a/lavianc2/internal/models"
)

type TaskRepo interface {
	CreateTask(ctx context.Context, t *models.Task) error
	UpdateTaskStatus(ctx context.Context, id uuid.UUID, status models.TaskStatus, output []byte, errMsg string) error
	ClaimPendingTasksForImplant(ctx context.Context, implantID uuid.UUID, limit int) ([]*models.Task, error)
	GetTask(ctx context.Context, id uuid.UUID) (*models.Task, error)
}

type taskRepo struct{ pool *pgxpool.Pool }

func (r *taskRepo) CreateTask(ctx context.Context, t *models.Task) error {
	argsJSON, err := json.Marshal(t.Args)
	if err != nil {
		return fmt.Errorf("storage: marshal args: %w", err)
	}
	query := `
		INSERT INTO tasks (id, implant_id, operator_id, command, args, payload, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err = r.pool.Exec(ctx, query,
		t.ID, t.ImplantID, t.OperatorID, t.Command,
		argsJSON, t.Payload, t.Status, t.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("storage: create task: %w", err)
	}
	return nil
}

func (r *taskRepo) UpdateTaskStatus(ctx context.Context, id uuid.UUID, status models.TaskStatus, output []byte, errMsg string) error {
	query := `
		UPDATE tasks SET status = $2, output = $3, error = $4,
			dispatched_at = CASE WHEN $2 = 'sent' THEN now() ELSE dispatched_at END,
			completed_at = CASE WHEN $2 IN ('completed','failed') THEN now() ELSE completed_at END
		WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id, status, output, errMsg)
	if err != nil {
		return fmt.Errorf("storage: update task status: %w", err)
	}
	return nil
}

func (r *taskRepo) ClaimPendingTasksForImplant(ctx context.Context, implantID uuid.UUID, limit int) ([]*models.Task, error) {
	if limit <= 0 {
		limit = 32
	}

	query := `
		WITH claimed AS (
			SELECT id FROM tasks
			WHERE implant_id = $1 AND status = 'pending'
			ORDER BY created_at ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE tasks
		SET status = 'sent', dispatched_at = now()
		WHERE id IN (SELECT id FROM claimed)
		RETURNING id, implant_id, operator_id, command, args, payload, status, output, error,
		          created_at, dispatched_at, completed_at`

	rows, err := r.pool.Query(ctx, query, implantID, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: claim pending tasks: %w", err)
	}
	defer rows.Close()

	var tasks []*models.Task
	for rows.Next() {
		t, err := scanTaskRow(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: rows error: %w", err)
	}
	return tasks, nil
}

func (r *taskRepo) GetTask(ctx context.Context, id uuid.UUID) (*models.Task, error) {
	query := `
		SELECT id, implant_id, operator_id, command, args, payload, status, output, error,
		       created_at, dispatched_at, completed_at
		FROM tasks WHERE id = $1`
	row := r.pool.QueryRow(ctx, query, id)
	t, err := scanTaskRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: get task: %w", err)
	}
	return t, nil
}

func scanTaskRow(row interface {
	Scan(dest ...any) error
}) (*models.Task, error) {
	t := &models.Task{}
	var (
		argsJSON []byte
		payload  []byte
		output   []byte
		errMsg   sql.NullString
	)

	if err := row.Scan(
		&t.ID, &t.ImplantID, &t.OperatorID, &t.Command,
		&argsJSON, &payload, &t.Status, &output, &errMsg,
		&t.CreatedAt, &t.DispatchedAt, &t.CompletedAt,
	); err != nil {
		return nil, err
	}

	if len(argsJSON) > 0 {
		if err := json.Unmarshal(argsJSON, &t.Args); err != nil {
			return nil, fmt.Errorf("storage: unmarshal args: %w", err)
		}
	}
	if payload != nil {
		t.Payload = payload
	}
	if output != nil {
		t.Output = output
	}
	if errMsg.Valid {
		t.Error = errMsg.String
	}
	return t, nil
}
