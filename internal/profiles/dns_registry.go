package profiles

import (
	"fmt"
	"sync"
)

type DNSRegistry struct {
	mu       sync.RWMutex
	profiles map[string]*DNSProfile
}

func NewDNSRegistry() *DNSRegistry {
	r := &DNSRegistry{profiles: make(map[string]*DNSProfile)}
	r.Register(DNSTXTProfile)
	r.Register(DNSAProfile)
	r.Register(DNSDoHProfile)
	return r
}

func (r *DNSRegistry) Register(p *DNSProfile) {
	if p == nil || p.Name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles[p.Name] = p
}

func (r *DNSRegistry) Get(name string) (*DNSProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[name]
	if !ok {
		return nil, fmt.Errorf("profiles: perfil DNS %q no encontrado", name)
	}
	return p, nil
}

func (r *DNSRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.profiles))
	for n := range r.profiles {
		names = append(names, n)
	}
	return names
}
