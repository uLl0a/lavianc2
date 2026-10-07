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

// ImplantRepo define las operaciones sobre la tabla implants.
type ImplantRepo interface {
	// Create inserta un nuevo implante (check-in inicial).
	Create(ctx context.Context, imp *models.Implant) error

	// Get obtiene un implante por su UUID.
	Get(ctx context.Context, id uuid.UUID) (*models.Implant, error)

	// GetBySessionKey obtiene un implante por su session_key público.
	// Devuelve (nil, nil) si no existe (patrón usado en el listener HTTPS).
	GetBySessionKey(ctx context.Context, sessionKey string) (*models.Implant, error)

	// UpdateCheckin actualiza los campos volátiles en cada check-in.
	UpdateCheckin(ctx context.Context, imp *models.Implant) error

	// UpdateStatus cambia el estado del implante (alive, sleeping, dead, killed).
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.ImplantStatus) error

	// UpdateSleep cambia el intervalo de sleep y jitter.
	UpdateSleep(ctx context.Context, id uuid.UUID, sleepSecs, jitter int) error

	// UpdateMetadata actualiza el JSONB de metadata.
	UpdateMetadata(ctx context.Context, id uuid.UUID, metadata map[string]any) error

	// List devuelve todos los implantes, ordenados por último check-in descendente.
	List(ctx context.Context) ([]*models.Implant, error)

	// ListByListener devuelve los implantes asociados a un listener.
	ListByListener(ctx context.Context, listenerID uuid.UUID) ([]*models.Implant, error)

	// Delete elimina un implante (cascade borra sus tareas).
	Delete(ctx context.Context, id uuid.UUID) error

	// MarkStaleAsDead marca como 'dead' los implantes que llevan sin
	// check-in más de max(5 min, 3 × sleep_interval). Devuelve los IDs
	// afectados para logging y limpieza posterior.
	MarkStaleAsDead(ctx context.Context) ([]uuid.UUID, error)
}

// implantRepo implementa ImplantRepo con pgxpool.
type implantRepo struct {
	pool *pgxpool.Pool
}

func (r *implantRepo) Create(ctx context.Context, imp *models.Implant) error {
	if imp.ID == uuid.Nil {
		imp.ID = uuid.New()
	}
	now := time.Now().UTC()
	if imp.FirstSeen.IsZero() {
		imp.FirstSeen = now
	}
	if imp.LastCheckIn.IsZero() {
		imp.LastCheckIn = now
	}
	if imp.Status == "" {
		imp.Status = models.ImplantAlive
	}
	if imp.SleepInterval <= 0 {
		imp.SleepInterval = 60
	}
	if imp.Jitter < 0 {
		imp.Jitter = 10
	}
	if imp.Metadata == nil {
		imp.Metadata = map[string]any{}
	}

	metadataJSON, err := json.Marshal(imp.Metadata)
	if err != nil {
		return fmt.Errorf("storage: marshal metadata: %w", err)
	}

	query := `
		INSERT INTO implants (
			id, session_key, hostname, username, os, arch, pid, process_name,
			internal_ip, external_ip, listener_id, public_key, status,
			sleep_interval, jitter, first_seen, last_check_in, metadata
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`

	_, err = r.pool.Exec(ctx, query,
		imp.ID,
		imp.SessionKey,
		imp.Hostname,
		imp.Username,
		imp.OS,
		imp.Arch,
		imp.PID,
		imp.ProcessName,
		imp.InternalIP,
		imp.ExternalIP,
		imp.ListenerID,
		imp.PublicKey,
		imp.Status,
		imp.SleepInterval,
		imp.Jitter,
		imp.FirstSeen,
		imp.LastCheckIn,
		metadataJSON,
	)
	if err != nil {
		return fmt.Errorf("storage: create implant: %w", err)
	}
	return nil
}

func (r *implantRepo) Get(ctx context.Context, id uuid.UUID) (*models.Implant, error) {
	query := `
		SELECT id, session_key, hostname, username, os, arch, pid, process_name,
		       internal_ip, external_ip, listener_id, public_key, status,
		       sleep_interval, jitter, first_seen, last_check_in, metadata
		FROM implants
		WHERE id = $1`

	return r.scanOne(ctx, query, id)
}

func (r *implantRepo) GetBySessionKey(ctx context.Context, sessionKey string) (*models.Implant, error) {
	query := `
		SELECT id, session_key, hostname, username, os, arch, pid, process_name,
		       internal_ip, external_ip, listener_id, public_key, status,
		       sleep_interval, jitter, first_seen, last_check_in, metadata
		FROM implants
		WHERE session_key = $1`

	return r.scanOne(ctx, query, sessionKey)
}

func (r *implantRepo) List(ctx context.Context) ([]*models.Implant, error) {
	query := `
		SELECT id, session_key, hostname, username, os, arch, pid, process_name,
		       internal_ip, external_ip, listener_id, public_key, status,
		       sleep_interval, jitter, first_seen, last_check_in, metadata
		FROM implants
		ORDER BY last_check_in DESC`

	return r.scanMany(ctx, query)
}

func (r *implantRepo) ListByListener(ctx context.Context, listenerID uuid.UUID) ([]*models.Implant, error) {
	query := `
		SELECT id, session_key, hostname, username, os, arch, pid, process_name,
		       internal_ip, external_ip, listener_id, public_key, status,
		       sleep_interval, jitter, first_seen, last_check_in, metadata
		FROM implants
		WHERE listener_id = $1
		ORDER BY last_check_in DESC`

	return r.scanMany(ctx, query, listenerID)
}

func (r *implantRepo) UpdateCheckin(ctx context.Context, imp *models.Implant) error {
	if imp.LastCheckIn.IsZero() {
		imp.LastCheckIn = time.Now().UTC()
	}

	query := `
		UPDATE implants
		SET hostname      = COALESCE(NULLIF($2, ''), hostname),
		    username      = COALESCE(NULLIF($3, ''), username),
		    os            = COALESCE(NULLIF($4, ''), os),
		    arch          = COALESCE(NULLIF($5, ''), arch),
		    pid           = CASE WHEN $6 > 0 THEN $6 ELSE pid END,
		    process_name  = COALESCE(NULLIF($7, ''), process_name),
		    internal_ip   = COALESCE(NULLIF($8, ''), internal_ip),
		    external_ip   = COALESCE(NULLIF($9, ''), external_ip),
		    public_key    = CASE WHEN length($10) > 0 THEN $10 ELSE public_key END,
		    status        = 'alive',
		    last_check_in = $11
		WHERE id = $1`

	tag, err := r.pool.Exec(ctx, query,
		imp.ID,
		imp.Hostname,
		imp.Username,
		imp.OS,
		imp.Arch,
		imp.PID,
		imp.ProcessName,
		imp.InternalIP,
		imp.ExternalIP,
		imp.PublicKey,
		imp.LastCheckIn,
	)
	if err != nil {
		return fmt.Errorf("storage: update checkin: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: implante %s no encontrado", imp.ID)
	}
	return nil
}

func (r *implantRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status models.ImplantStatus) error {
	query := `UPDATE implants SET status = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("storage: update implant status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: implante %s no encontrado", id)
	}
	return nil
}

func (r *implantRepo) UpdateSleep(ctx context.Context, id uuid.UUID, sleepSecs, jitter int) error {
	if sleepSecs <= 0 {
		return fmt.Errorf("storage: sleep_interval debe ser > 0")
	}
	if jitter < 0 || jitter > 100 {
		return fmt.Errorf("storage: jitter debe estar entre 0 y 100")
	}
	query := `UPDATE implants SET sleep_interval = $2, jitter = $3 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, sleepSecs, jitter)
	if err != nil {
		return fmt.Errorf("storage: update sleep: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: implante %s no encontrado", id)
	}
	return nil
}

func (r *implantRepo) UpdateMetadata(ctx context.Context, id uuid.UUID, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("storage: marshal metadata: %w", err)
	}
	query := `UPDATE implants SET metadata = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, metadataJSON)
	if err != nil {
		return fmt.Errorf("storage: update metadata: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: implante %s no encontrado", id)
	}
	return nil
}

func (r *implantRepo) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM implants WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("storage: delete implant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: implante %s no encontrado", id)
	}
	return nil
}

// scanOne ejecuta una query que devuelve una fila y la mapea a Implant.
// Devuelve (nil, nil) si no hay filas.
func (r *implantRepo) scanOne(ctx context.Context, query string, arg any) (*models.Implant, error) {
	imp := &models.Implant{}
	var metadataJSON []byte

	err := r.pool.QueryRow(ctx, query, arg).Scan(
		&imp.ID,
		&imp.SessionKey,
		&imp.Hostname,
		&imp.Username,
		&imp.OS,
		&imp.Arch,
		&imp.PID,
		&imp.ProcessName,
		&imp.InternalIP,
		&imp.ExternalIP,
		&imp.ListenerID,
		&imp.PublicKey,
		&imp.Status,
		&imp.SleepInterval,
		&imp.Jitter,
		&imp.FirstSeen,
		&imp.LastCheckIn,
		&metadataJSON,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: scan implant: %w", err)
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &imp.Metadata); err != nil {
			return nil, fmt.Errorf("storage: unmarshal metadata: %w", err)
		}
	}
	return imp, nil
}

// scanMany ejecuta una query que devuelve varias filas.
func (r *implantRepo) scanMany(ctx context.Context, query string, args ...any) ([]*models.Implant, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: query implants: %w", err)
	}
	defer rows.Close()

	var imps []*models.Implant
	for rows.Next() {
		imp := &models.Implant{}
		var metadataJSON []byte

		if err := rows.Scan(
			&imp.ID,
			&imp.SessionKey,
			&imp.Hostname,
			&imp.Username,
			&imp.OS,
			&imp.Arch,
			&imp.PID,
			&imp.ProcessName,
			&imp.InternalIP,
			&imp.ExternalIP,
			&imp.ListenerID,
			&imp.PublicKey,
			&imp.Status,
			&imp.SleepInterval,
			&imp.Jitter,
			&imp.FirstSeen,
			&imp.LastCheckIn,
			&metadataJSON,
		); err != nil {
			return nil, fmt.Errorf("storage: scan implant: %w", err)
		}
		if len(metadataJSON) > 0 {
			_ = json.Unmarshal(metadataJSON, &imp.Metadata)
		}
		imps = append(imps, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: rows error: %w", err)
	}
	return imps, nil
}

func (r *implantRepo) MarkStaleAsDead(ctx context.Context) ([]uuid.UUID, error) {
	query := `
		UPDATE implants
		SET status = 'dead'
		WHERE status IN ('alive', 'sleeping')
		  AND last_check_in < now() - make_interval(
		      secs => GREATEST(300, sleep_interval * 3)
		  )
		RETURNING id`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("storage: mark stale as dead: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("storage: scan implant id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: rows error: %w", err)
	}
	return ids, nil
}
