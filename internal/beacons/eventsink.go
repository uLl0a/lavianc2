package beacons

import (
	"context"

	"github.com/google/uuid"
	"github.com/uLl0a/lavianc2/internal/events"
)

// BusEventRecorder implementa EventRecorder publicando en el bus de
// eventos existente y persistiendo en BeaconStore si hay uno.
type BusEventRecorder struct {
	bus   *events.Bus
	store BeaconStore
}

// NewBusEventRecorder crea el recorder.
func NewBusEventRecorder(bus *events.Bus, store BeaconStore) *BusEventRecorder {
	return &BusEventRecorder{bus: bus, store: store}
}

// Record publica el evento en el bus y lo persiste como auditoría.
func (r *BusEventRecorder) Record(ctx context.Context, beaconID uuid.UUID, kind FailureKind, detail string) {
	if r.bus != nil {
		r.bus.Publish(ctx, events.Event{
			Topic: events.TopicOperatorAction,
			Payload: map[string]any{
				"beacon_id": beaconID.String(),
				"action":    "beacon." + string(kind),
				"detail":    detail,
			},
		})
	}
	if r.store != nil {
		_ = r.store.RecordEvent(ctx, beaconID, kind, detail)
	}
}
