package models

import (
	"time"

	"github.com/google/uuid"
)

// OperatorStatus representa el estado de un operador.
type OperatorStatus string

const (
	OperatorActive   OperatorStatus = "active"
	OperatorDisabled OperatorStatus = "disabled"
)

// Operator es un miembro del equipo Red Team con acceso al Team Server.
type Operator struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string // bcrypt
	Role         string // "admin", "operator", "viewer"
	Status       OperatorStatus
	CreatedAt    time.Time
	LastSeenAt   *time.Time
}

// ListenerType define el protocolo de transporte.
type ListenerType string

const (
	ListenerHTTPS ListenerType = "https"
	ListenerDNS   ListenerType = "dns"
	ListenerMTLS  ListenerType = "mtls"
	ListenerHTTP  ListenerType = "http"
	ListenerQUIC  ListenerType = "quic"
)

// Listener es un endpoint de C2 que recibe check-ins de implantes.
type Listener struct {
	ID        uuid.UUID
	Name      string
	Type      ListenerType
	BindAddr  string
	Port      int
	Domain    string
	TLSCert   []byte
	TLSKey    []byte
	Config    map[string]any
	Active    bool
	CreatedAt time.Time
}

// ImplantStatus refleja el ciclo de vida de una sesión de implante.
type ImplantStatus string

const (
	ImplantAlive    ImplantStatus = "alive"
	ImplantSleeping ImplantStatus = "sleeping"
	ImplantDead     ImplantStatus = "dead"
	ImplantKilled   ImplantStatus = "killed"
)

// Implant representa una sesión activa de un agente en un host comprometido.
type Implant struct {
	ID            uuid.UUID
	SessionKey    string
	Hostname      string
	Username      string
	OS            string
	Arch          string
	PID           int
	ProcessName   string
	InternalIP    string
	ExternalIP    string
	ListenerID    uuid.UUID
	PublicKey     []byte
	Status        ImplantStatus
	SleepInterval int
	Jitter        int
	FirstSeen     time.Time
	LastCheckIn   time.Time
	Metadata      map[string]any
}

// TaskStatus es el estado de una tarea enviada a un implante.
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskSent      TaskStatus = "sent"
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
)

// Task es una unidad de trabajo asignada a un implante.
type Task struct {
	ID           uuid.UUID
	ImplantID    uuid.UUID
	OperatorID   uuid.UUID
	Command      string
	Args         []string
	Payload      []byte
	Status       TaskStatus
	Output       []byte
	Error        string
	CreatedAt    time.Time
	DispatchedAt *time.Time
	CompletedAt  *time.Time
}

// EventLevel define la severidad de un evento.
type EventLevel string

const (
	LevelDebug EventLevel = "debug"
	LevelInfo  EventLevel = "info"
	LevelWarn  EventLevel = "warn"
	LevelError EventLevel = "error"
)

// Event es una entrada de auditoría / log estructurado.
type Event struct {
	ID         uuid.UUID
	Level      EventLevel
	Category   string
	Message    string
	OperatorID *uuid.UUID
	ImplantID  *uuid.UUID
	TaskID     *uuid.UUID
	ListenerID *uuid.UUID
	Data       map[string]any
	CreatedAt  time.Time
}

// Build registra una compilación de implante.
type Build struct {
	ID          uuid.UUID
	OperatorID  *uuid.UUID
	ListenerID  *uuid.UUID
	ProfileName string
	TargetOS    string
	TargetArch  string
	Format      string
	ListenerURL string
	SleepSecs   int
	JitterPerc  int
	Obfuscate   bool
	Compress    bool
	OutputPath  string
	SizeBytes   int64
	DurationMs  int64
	CreatedAt   time.Time
}
