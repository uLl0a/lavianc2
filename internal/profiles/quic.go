package profiles

import (
	"fmt"
	"sync"
	"time"
)

// QUICProfile describe cómo se presenta el transporte QUIC al exterior.
//
// QUIC no tiene headers HTTP ni User-Agent ni URIs. Lo que sí tiene es
// ALPN (Application-Layer Protocol Negotiation), una lista de protocolos
// que el cliente anuncia en el handshake TLS 1.3 embebido. Los servidores
// HTTP/3 anuncian "h3"; los navegadores modernos lo ofrecen. Un C2 que
// anuncie "h3" se mimetiza con HTTP/3 a efectos del handshake.
type QUICProfile struct {
	Name string

	// Host se usa como SNI. Vacío = usar el host del ListenerURL.
	Host string

	// ALPN es la lista de protocolos que se anuncian. Cliente y servidor
	// deben compartir al menos uno para que la negociación funcione.
	ALPN []string

	// MaxIdleTimeout: cuánto mantiene la conexión abierta sin tráfico.
	// Abrimos una conexión nueva por beacon, así que no importa mucho.
	MaxIdleTimeout time.Duration

	// KeepAlivePeriod envía PINGs para mantener viva la conexión.
	// 0 deshabilita. Para beacons cortos, dejar en 0.
	KeepAlivePeriod time.Duration
}

var QUICH3Profile = &QUICProfile{
	Name:            "quic-h3",
	Host:            "",
	ALPN:            []string{"h3"},
	MaxIdleTimeout:  30 * time.Second,
	KeepAlivePeriod: 0,
}

var QUICH3DraftProfile = &QUICProfile{
	Name:            "quic-h3-draft",
	Host:            "",
	ALPN:            []string{"h3-29", "h3", "h3-32"},
	MaxIdleTimeout:  30 * time.Second,
	KeepAlivePeriod: 0,
}

// QUICRegistry gestiona los perfiles QUIC disponibles.
type QUICRegistry struct {
	mu       sync.RWMutex
	profiles map[string]*QUICProfile
}

func NewQUICRegistry() *QUICRegistry {
	r := &QUICRegistry{profiles: make(map[string]*QUICProfile)}
	r.Register(QUICH3Profile)
	r.Register(QUICH3DraftProfile)
	return r
}

func (r *QUICRegistry) Register(p *QUICProfile) {
	if p == nil || p.Name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles[p.Name] = p
}

func (r *QUICRegistry) Get(name string) (*QUICProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[name]
	if !ok {
		return nil, fmt.Errorf("profiles: perfil QUIC %q no encontrado", name)
	}
	return p, nil
}

func (r *QUICRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.profiles))
	for n := range r.profiles {
		names = append(names, n)
	}
	return names
}
