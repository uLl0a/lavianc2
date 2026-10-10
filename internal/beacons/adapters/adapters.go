// Package adapters define perfiles versionados de protocolo y un registry
// que reutiliza los mecanismos de comunicación existentes (los listeners
// HTTPS/DNS/QUIC ya vivos). WebSocket se marca como extensión hasta que su
// listener esté activo.
package adapters

import (
	"errors"
	"fmt"
	"sync"
)

// Protocol identifica un transporte C2.
type Protocol string

const (
	ProtoHTTPS     Protocol = "https"
	ProtoDNS       Protocol = "dns"
	ProtoQUIC      Protocol = "quic"
	ProtoWebSocket Protocol = "websocket"
)

// Profile es un perfil versionado de un protocolo.
type Profile struct {
	Protocol    Protocol
	Version     int
	ListenerID  string // identificador del listener subyacente (si aplica)
	Implemented bool   // si el transporte existe hoy en el servidor
}

// Registry mantiene los adaptadores de protocolo disponibles.
type Registry struct {
	mu        sync.RWMutex
	adapters  map[Protocol]Profile
	listeners map[Protocol]string
}

// NewRegistry crea un registry precargado con los protocolos reales del
// proyecto. HTTPS/DNS/QUIC ya están implementados; WebSocket es una
// extensión (implemented=false) hasta que su listener exista.
func NewRegistry(httpsID, dnsID, quicID string) *Registry {
	r := &Registry{
		adapters:  make(map[Protocol]Profile),
		listeners: make(map[Protocol]string),
	}
	r.adapters[ProtoHTTPS] = Profile{Protocol: ProtoHTTPS, Version: 1, ListenerID: httpsID, Implemented: true}
	r.adapters[ProtoDNS] = Profile{Protocol: ProtoDNS, Version: 1, ListenerID: dnsID, Implemented: true}
	r.adapters[ProtoQUIC] = Profile{Protocol: ProtoQUIC, Version: 1, ListenerID: quicID, Implemented: true}
	// WebSocket: requiere extensión (no hay listener WS aún).
	r.adapters[ProtoWebSocket] = Profile{Protocol: ProtoWebSocket, Version: 0, Implemented: false}
	return r
}

// Register añade o actualiza un adaptador. Rechista versiones menores.
func (r *Registry) Register(p Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.Protocol == "" {
		return errors.New("adapters: protocolo vacío")
	}
	if p.Version < 0 {
		return errors.New("adapters: versión inválida")
	}
	if existing, ok := r.adapters[p.Protocol]; ok && p.Version < existing.Version {
		return fmt.Errorf("adapters: no se puede registrar %s v%d (ya existe v%d)",
			p.Protocol, p.Version, existing.Version)
	}
	r.adapters[p.Protocol] = p
	if p.ListenerID != "" {
		r.listeners[p.Protocol] = p.ListenerID
	}
	return nil
}

// Get devuelve el perfil de un protocolo.
func (r *Registry) Get(proto Protocol) (Profile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.adapters[proto]
	return p, ok
}

// Implemented informa si un protocolo tiene transporte real disponible.
func (r *Registry) Implemented(proto Protocol) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.adapters[proto]
	return ok && p.Implemented
}

// List enumera todos los adaptadores.
func (r *Registry) List() []Profile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Profile, 0, len(r.adapters))
	for _, p := range r.adapters {
		out = append(out, p)
	}
	return out
}
