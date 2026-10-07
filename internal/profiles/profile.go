package profiles

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

type Profile struct {
	Name         string
	UserAgent    string
	Host         string
	URIs         []string
	Headers      map[string]string
	Padding      bool
	PaddingRange [2]int
	Jitter       int
}

func (p *Profile) ApplyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", p.UserAgent)
	req.Host = p.Host

	for k, v := range p.Headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}

	switch p.Name {
	case "office365":
		req.Header.Set("X-Ms-Client-Request-Id", newUUID())
		req.Header.Set("X-Ms-Client-Session-Id", newUUID())
	case "slack":
		req.Header.Set("X-Slack-Request-Id", newUUID())
		req.Header.Set("X-Slack-Req-Id", newUUID())
		req.Header.Set("Authorization", "Bearer xoxb-"+randomToken(48))
	case "cdn":
		req.Header.Set("CF-Ray", randomHex(16)+"-"+randomColo())
		req.Header.Set("CF-Connecting-IP", "203.0.113."+randomDigits(1, 254))
		req.Header.Set("CF-IPCountry", randomCountry())
		req.Header.Set("CDN-Loop", "cloudflare; loops=1")
	case "jquery":
		req.Header.Set("If-None-Match", `"`+randomHex(32)+`"`)
		req.Header.Set("If-Modified-Since", randomPastDate())
	case "ocsp":
		nonce := randomBytes(16 + rand.Intn(17)) // 16-32 bytes
		req.Header.Set("X-OCSP-Nonce", base64.StdEncoding.EncodeToString(nonce))
		req.Header.Set("X-OCSP-Request-Id", randomHex(32))

	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		rand.Read(b)
	}
	return b
}

func randomPastDate() string {
	daysAgo := rand.Intn(30)
	t := time.Now().AddDate(0, 0, -daysAgo)
	return t.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}

func (p *Profile) RandomURI() string {
	if len(p.URIs) == 0 {
		return "/"
	}
	return p.URIs[rand.Intn(len(p.URIs))]
}

func (p *Profile) PadPayload(payload []byte) []byte {
	if !p.Padding {
		return payload
	}
	if p.PaddingRange[1] <= p.PaddingRange[0] {
		return payload
	}
	padLen := p.PaddingRange[0] + rand.Intn(p.PaddingRange[1]-p.PaddingRange[0])
	pad := make([]byte, padLen)
	if _, err := crand.Read(pad); err != nil {
		return payload
	}
	return append(payload, pad...)
}

func (p *Profile) JitteredSleep(base time.Duration) time.Duration {
	if p.Jitter <= 0 || base <= 0 {
		return base
	}
	jitter := base * time.Duration(p.Jitter) / 100
	if jitter <= 0 {
		return base
	}
	return base + time.Duration(rand.Int63n(int64(jitter)))
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type Registry struct {
	mu       sync.RWMutex
	profiles map[string]*Profile
}

func NewRegistry() *Registry {
	r := &Registry{profiles: make(map[string]*Profile)}
	r.Register(Office365Profile)
	r.Register(SlackProfile)
	r.Register(CDNProfile)
	r.Register(JQueryProfile)
	r.Register(OCSPProfile)
	return r
}

func (r *Registry) Register(p *Profile) {
	if p == nil || p.Name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles[p.Name] = p
}

func (r *Registry) Get(name string) (*Profile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[name]
	if !ok {
		return nil, fmt.Errorf("profiles: perfil %q no encontrado", name)
	}
	return p, nil
}

func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.profiles))
	for n := range r.profiles {
		names = append(names, n)
	}
	return names
}

func randomToken(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randomHex(n int) string {
	const charset = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randomColo() string {
	colos := []string{
		"SJC", "LAX", "SEA", "DFW", "ORD", "IAD", "EWR", "MIA",
		"LHR", "AMS", "FRA", "CDG", "MAD", "FCO", "WAW",
		"NRT", "HKG", "SIN", "SYD", "GRU", "EZE",
	}
	return colos[rand.Intn(len(colos))]
}

func randomCountry() string {
	countries := []string{
		"US", "CA", "MX", "BR", "AR", "GB", "DE", "FR", "ES", "IT",
		"NL", "SE", "NO", "PL", "JP", "KR", "CN", "IN", "AU", "NZ",
	}
	return countries[rand.Intn(len(countries))]
}

func randomDigits(min, max int) string {
	n := min + rand.Intn(max-min+1)
	return fmt.Sprintf("%d", n)
}
