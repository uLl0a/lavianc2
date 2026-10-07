package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionKeyRepo define la persistencia de claves de sesión.
type SessionKeyRepo interface {
	Save(ctx context.Context, implantID uuid.UUID, c2ToBeacon, beaconToC2 []byte, msgCount, rekeyEvery uint64) error
	Load(ctx context.Context, implantID uuid.UUID) (c2ToBeacon, beaconToC2 []byte, msgCount, rekeyEvery uint64, err error)
	Delete(ctx context.Context, implantID uuid.UUID) error
}

type sessionKeyRepo struct {
	pool *pgxpool.Pool
}

// Save hace UPSERT de las claves de sesión.
func (r *sessionKeyRepo) Save(
	ctx context.Context,
	implantID uuid.UUID,
	c2ToBeacon, beaconToC2 []byte,
	msgCount, rekeyEvery uint64,
) error {
	query := `
		INSERT INTO session_keys (implant_id, c2_to_beacon, beacon_to_c2, msg_count, rekey_every, last_rekey_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (implant_id) DO UPDATE
		SET c2_to_beacon  = EXCLUDED.c2_to_beacon,
		    beacon_to_c2  = EXCLUDED.beacon_to_c2,
		    msg_count     = EXCLUDED.msg_count,
		    rekey_every   = EXCLUDED.rekey_every,
		    last_rekey_at = CASE
		        WHEN EXCLUDED.msg_count < session_keys.msg_count THEN now()
		        ELSE session_keys.last_rekey_at
		    END`

	_, err := r.pool.Exec(ctx, query,
		implantID,
		c2ToBeacon,
		beaconToC2,
		int64(msgCount),
		int64(rekeyEvery),
	)
	if err != nil {
		return fmt.Errorf("storage: save session keys: %w", err)
	}
	return nil
}

// Load recupera las claves de sesión. Devuelve (nil, nil, 0, 0, nil)
// si no existe la sesión.
func (r *sessionKeyRepo) Load(
	ctx context.Context,
	implantID uuid.UUID,
) (c2ToBeacon, beaconToC2 []byte, msgCount, rekeyEvery uint64, err error) {
	query := `
		SELECT c2_to_beacon, beacon_to_c2, msg_count, rekey_every
		FROM session_keys
		WHERE implant_id = $1`

	var msgCountI, rekeyEveryI int64
	err = r.pool.QueryRow(ctx, query, implantID).Scan(
		&c2ToBeacon, &beaconToC2, &msgCountI, &rekeyEveryI,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, 0, 0, nil
		}
		return nil, nil, 0, 0, fmt.Errorf("storage: load session keys: %w", err)
	}
	return c2ToBeacon, beaconToC2, uint64(msgCountI), uint64(rekeyEveryI), nil
}

// Delete elimina las claves de una sesión.
func (r *sessionKeyRepo) Delete(ctx context.Context, implantID uuid.UUID) error {
	query := `DELETE FROM session_keys WHERE implant_id = $1`
	_, err := r.pool.Exec(ctx, query, implantID)
	if err != nil {
		return fmt.Errorf("storage: delete session keys: %w", err)
	}
	return nil
}
