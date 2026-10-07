package listeners

import (
	"context"

	"github.com/google/uuid"
)

type ListenerMetadata struct {
	ID   uuid.UUID
	Name string
	Type string
}

type Listener interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error

	Metadata() ListenerMetadata
}
