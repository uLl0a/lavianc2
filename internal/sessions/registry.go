package sessions

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Registry mantiene las sesiones vivas en memoria.
type Registry struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*Session
}

type Session struct {
	ImplantID uuid.UUID
	LastSeen  time.Time
	pending   chan uuid.UUID
}

func NewRegistry() *Registry {
	return &Registry{sessions: make(map[uuid.UUID]*Session)}
}

func (r *Registry) Register(id uuid.UUID) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, exists := r.sessions[id]
	if !exists {
		s = &Session{ImplantID: id, pending: make(chan uuid.UUID, 256)}
		r.sessions[id] = s
	}
	s.LastSeen = time.Now().UTC()
	return s
}

func (r *Registry) Unregister(id uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[id]; ok {
		close(s.pending)
		delete(r.sessions, id)
	}
}

func (r *Registry) IsOnline(id uuid.UUID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.sessions[id]
	return ok
}

func (r *Registry) NotifyPendingTask(ctx context.Context, implantID, taskID uuid.UUID) error {
	r.mu.RLock()
	s, ok := r.sessions[implantID]
	r.mu.RUnlock()
	if !ok {
		return nil // pendiente en DB hasta próximo check-in
	}
	select {
	case s.pending <- taskID:
	case <-ctx.Done():
	}
	return nil
}

// PendingChannel devuelve el canal de tareas pendientes de una sesión.
func (r *Registry) PendingChannel(id uuid.UUID) <-chan uuid.UUID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.sessions[id]; ok {
		return s.pending
	}
	return nil
}
