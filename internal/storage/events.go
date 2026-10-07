package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uLl0a/lavianc2/internal/models"
)

// EventFilter permite filtrar eventos en la consulta.
type EventFilter struct {
	Level      models.EventLevel // opcional
	Category   string            // opcional
	OperatorID *uuid.UUID        // opcional
	ImplantID  *uuid.UUID        // opcional
	TaskID     *uuid.UUID        // opcional
	Since      *time.Time        // opcional
	Until      *time.Time        // opcional
	Limit      int               // opcional; 0 = sin límite (default 100)
	Offset     int               // opcional
}

// EventRepo define las operaciones sobre la tabla events.
type EventRepo interface {
	// Create inserta un evento de auditoría.
	Create(ctx context.Context, ev *models.Event) error

	// List devuelve eventos que cumplen el filtro, ordenados por fecha descendente.
	List(ctx context.Context, filter EventFilter) ([]*models.Event, error)

	// Count devuelve el número total de eventos que cumplen el filtro.
	Count(ctx context.Context, filter EventFilter) (int64, error)

	// DeleteOlderThan borra eventos anteriores a una fecha (para retención).
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}

// eventRepo implementa EventRepo con pgxpool.
type eventRepo struct {
	pool *pgxpool.Pool
}

func (r *eventRepo) Create(ctx context.Context, ev *models.Event) error {
	if ev.ID == uuid.Nil {
		ev.ID = uuid.New()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	if ev.Level == "" {
		ev.Level = models.LevelInfo
	}
	if ev.Data == nil {
		ev.Data = map[string]any{}
	}

	dataJSON, err := json.Marshal(ev.Data)
	if err != nil {
		return fmt.Errorf("storage: marshal event data: %w", err)
	}

	query := `
		INSERT INTO events (
			id, level, category, message, operator_id, implant_id, task_id, data, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = r.pool.Exec(ctx, query,
		ev.ID,
		ev.Level,
		ev.Category,
		ev.Message,
		ev.OperatorID,
		ev.ImplantID,
		ev.TaskID,
		dataJSON,
		ev.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("storage: create event: %w", err)
	}
	return nil
}

func (r *eventRepo) List(ctx context.Context, filter EventFilter) ([]*models.Event, error) {
	query, args := r.buildListQuery(filter, false)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: query events: %w", err)
	}
	defer rows.Close()

	var events []*models.Event
	for rows.Next() {
		ev := &models.Event{}
		var dataJSON []byte

		if err := rows.Scan(
			&ev.ID,
			&ev.Level,
			&ev.Category,
			&ev.Message,
			&ev.OperatorID,
			&ev.ImplantID,
			&ev.TaskID,
			&dataJSON,
			&ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("storage: scan event: %w", err)
		}
		if len(dataJSON) > 0 {
			_ = json.Unmarshal(dataJSON, &ev.Data)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: rows error: %w", err)
	}
	return events, nil
}

func (r *eventRepo) Count(ctx context.Context, filter EventFilter) (int64, error) {
	query, args := r.buildListQuery(filter, true)

	var count int64
	if err := r.pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("storage: count events: %w", err)
	}
	return count, nil
}

func (r *eventRepo) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	query := `DELETE FROM events WHERE created_at < $1`
	tag, err := r.pool.Exec(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("storage: delete old events: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *eventRepo) buildListQuery(filter EventFilter, count bool) (string, []any) {
	var (
		query  string
		args   []any
		where  string
		argIdx = 1
	)

	if count {
		query = `SELECT COUNT(*) FROM events`
	} else {
		query = `
			SELECT id, level, category, message, operator_id, implant_id, task_id, data, created_at
			FROM events`
	}

	// Construir WHERE dinámicamente
	addCond := func(cond string, arg any) {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += fmt.Sprintf(cond, argIdx)
		args = append(args, arg)
		argIdx++
	}

	if filter.Level != "" {
		addCond("level = $%d", filter.Level)
	}
	if filter.Category != "" {
		addCond("category = $%d", filter.Category)
	}
	if filter.OperatorID != nil {
		addCond("operator_id = $%d", *filter.OperatorID)
	}
	if filter.ImplantID != nil {
		addCond("implant_id = $%d", *filter.ImplantID)
	}
	if filter.TaskID != nil {
		addCond("task_id = $%d", *filter.TaskID)
	}
	if filter.Since != nil {
		addCond("created_at >= $%d", *filter.Since)
	}
	if filter.Until != nil {
		addCond("created_at <= $%d", *filter.Until)
	}

	query += where

	if !count {
		query += " ORDER BY created_at DESC"

		// Límite por defecto para evitar devolver miles de filas
		limit := filter.Limit
		if limit <= 0 {
			limit = 100
		}
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, limit)
		argIdx++

		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIdx)
			args = append(args, filter.Offset)
		}
	}

	return query, args
}
