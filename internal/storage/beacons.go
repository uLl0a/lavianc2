package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uLl0a/lavianc2/internal/beacons"
)

// beaconRepo implementa beacons.BeaconStore con pgxpool.
type beaconRepo struct {
	pool *pgxpool.Pool
}

// NewBeaconRepo crea el repo. Expone la interfaz beacons.BeaconStore.
func NewBeaconRepo(pool *pgxpool.Pool) beacons.BeaconStore {
	return &beaconRepo{pool: pool}
}

func (r *beaconRepo) SaveGroup(ctx context.Context, g *beacons.BeaconGroup) error {
	q := `INSERT INTO beacon_groups (id, name, profile) VALUES ($1,$2,$3)
	      ON CONFLICT (id) DO UPDATE SET name=$2, profile=$3`
	_, err := r.pool.Exec(ctx, q, g.ID, g.Name, string(g.Profile))
	if err != nil {
		return fmt.Errorf("storage: save beacon group: %w", err)
	}
	return nil
}

func (r *beaconRepo) GetGroup(ctx context.Context, id uuid.UUID) (*beacons.BeaconGroup, error) {
	q := `SELECT id, name, profile FROM beacon_groups WHERE id=$1`
	var g beacons.BeaconGroup
	err := r.pool.QueryRow(ctx, q, id).Scan(&g.ID, &g.Name, &g.Profile)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (r *beaconRepo) ListGroups(ctx context.Context) ([]*beacons.BeaconGroup, error) {
	q := `SELECT id, name, profile FROM beacon_groups ORDER BY name`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*beacons.BeaconGroup
	for rows.Next() {
		var g beacons.BeaconGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Profile); err != nil {
			return nil, err
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}

func (r *beaconRepo) Save(ctx context.Context, b *beacons.Beacon) error {
	meta, err := json.Marshal(b.Metadata)
	if err != nil {
		return err
	}
	q := `INSERT INTO beacons
	      (id, implant_id, group_id, name, profile, state, fail_streak, max_fails, last_check_in, metadata)
	      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	      ON CONFLICT (id) DO UPDATE SET
	        implant_id=$2, group_id=$3, name=$4, profile=$5, state=$6, fail_streak=$7,
	        max_fails=$8, last_check_in=$9, metadata=$10`
	_, err = r.pool.Exec(ctx, q, b.ID, b.ImplantID, b.GroupID, b.Name, string(b.Profile),
		string(b.State), b.FailStreak, b.MaxFails, b.LastCheckIn, meta)
	if err != nil {
		return fmt.Errorf("storage: save beacon: %w", err)
	}
	return nil
}

func (r *beaconRepo) Get(ctx context.Context, id uuid.UUID) (*beacons.Beacon, error) {
	q := `SELECT id, implant_id, group_id, name, profile, state, fail_streak, max_fails, last_check_in, metadata
	      FROM beacons WHERE id=$1`
	var b beacons.Beacon
	var meta []byte
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&b.ID, &b.ImplantID, &b.GroupID, &b.Name, &b.Profile, &b.State,
		&b.FailStreak, &b.MaxFails, &b.LastCheckIn, &meta)
	if err != nil {
		return nil, err
	}
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &b.Metadata)
	}
	return &b, nil
}

func (r *beaconRepo) List(ctx context.Context) ([]*beacons.Beacon, error) {
	q := `SELECT id, implant_id, group_id, name, profile, state, fail_streak, max_fails, last_check_in, metadata
	      FROM beacons ORDER BY name`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*beacons.Beacon
	for rows.Next() {
		var b beacons.Beacon
		var meta []byte
		if err := rows.Scan(&b.ID, &b.ImplantID, &b.GroupID, &b.Name, &b.Profile, &b.State,
			&b.FailStreak, &b.MaxFails, &b.LastCheckIn, &meta); err != nil {
			return nil, err
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &b.Metadata)
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

func (r *beaconRepo) SetState(ctx context.Context, id uuid.UUID, state beacons.HealthState, failStreak int) error {
	q := `UPDATE beacons SET state=$2, fail_streak=$3 WHERE id=$1`
	_, err := r.pool.Exec(ctx, q, id, string(state), failStreak)
	if err != nil {
		return fmt.Errorf("storage: set beacon state: %w", err)
	}
	return nil
}

func (r *beaconRepo) SetProfile(ctx context.Context, id uuid.UUID, profile beacons.Profile) error {
	q := `UPDATE beacons SET profile=$2 WHERE id=$1`
	_, err := r.pool.Exec(ctx, q, id, string(profile))
	if err != nil {
		return fmt.Errorf("storage: set beacon profile: %w", err)
	}
	return nil
}

func (r *beaconRepo) RecordEvent(ctx context.Context, beaconID uuid.UUID, kind beacons.FailureKind, detail string) error {
	q := `INSERT INTO beacon_events (beacon_id, kind, detail) VALUES ($1,$2,$3)`
	_, err := r.pool.Exec(ctx, q, beaconID, string(kind), detail)
	if err != nil {
		return fmt.Errorf("storage: record beacon event: %w", err)
	}
	return nil
}

var _ = time.Now // evitar import no usado si se refactoriza
