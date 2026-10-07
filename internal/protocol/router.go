package protocol

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Handler procesa un envelope y devuelve la respuesta.
type Handler func(ctx context.Context, env *Envelope) (*Envelope, error)

// Router enruta envelopes a handlers basándose en el MessageType.
// Patrón idéntico al de Sliver: envelope → router → handler específico.
type Router struct {
	mu       sync.RWMutex
	handlers map[MessageType]Handler
	log      *slog.Logger
}

// NewRouter crea un router vacío.
func NewRouter(log *slog.Logger) *Router {
	return &Router{
		handlers: make(map[MessageType]Handler),
		log:      log,
	}
}

// Register registra un handler para un tipo de mensaje.
// Retorna error si ya existe un handler para ese tipo.
func (r *Router) Register(msgType MessageType, h Handler) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.handlers[msgType]; exists {
		return fmt.Errorf("protocol: handler duplicado para tipo %d", msgType)
	}
	r.handlers[msgType] = h
	return nil
}

// MustRegister registra o hace panic (para uso en init).
func (r *Router) MustRegister(msgType MessageType, h Handler) {
	if err := r.Register(msgType, h); err != nil {
		panic(err)
	}
}

// Dispatch procesa un envelope y devuelve la respuesta.
func (r *Router) Dispatch(ctx context.Context, env *Envelope) (*Envelope, error) {
	r.mu.RLock()
	h, ok := r.handlers[env.Type]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("protocol: sin handler para tipo %d", env.Type)
	}

	resp, err := h(ctx, env)
	if err != nil {
		r.log.Warn("handler error", "type", env.Type, "err", err)
		return nil, err
	}
	return resp, nil
}

// HandleRaw procesa datos crudos: deserializa envelope y despacha.
func (r *Router) HandleRaw(ctx context.Context, data []byte) (*Envelope, error) {
	env, err := UnmarshalEnvelope(data)
	if err != nil {
		return nil, err
	}
	return r.Dispatch(ctx, env)
}
