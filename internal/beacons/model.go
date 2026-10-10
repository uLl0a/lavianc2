package beacons

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Profile clasifica un beacon por su papel operativo.
type Profile string

const (
	// ProfileShortHaul: beacon interactivo, latencia baja, acepta cargas
	// dinámicas pesadas (BOF, .NET) y túneles interactivos (hVNC).
	ProfileShortHaul Profile = "short-haul"

	// ProfileLongHaul: beacon de supervivencia, sleep alto, solo comandos
	// ligeros. NUNCA recibe BOF/.NET/hVNC.
	ProfileLongHaul Profile = "long-haul"
)

// ParseProfile valida y normaliza un perfil.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileShortHaul, ProfileLongHaul:
		return Profile(s), nil
	case "":
		return "", errors.New("beacons: perfil vacío")
	default:
		return "", fmt.Errorf("beacons: perfil %q inválido (usar short-haul|long-haul)", s)
	}
}

// HealthState es el estado operativo de un beacon en la máquina de estados.
type HealthState string

const (
	// StateOnline: beacon respondiendo dentro del umbral.
	StateOnline HealthState = "online"

	// StateDegraded: un fallo registrado, aún dentro de tolerancia.
	StateDegraded HealthState = "degraded"

	// StateOffline: MaxFails fallos consecutivos sin recuperación.
	StateOffline HealthState = "offline"

	// StateAdminStop: detención administrativa (operator deliberado).
	StateAdminStop HealthState = "admin-stop"

	// StateInternalErr: error interno del agente/beacon.
	StateInternalErr HealthState = "internal-err"
)

// FailureKind clasifica la causa de un fallo para distinguir pérdida de
// transporte, agente no disponible, detención administrativa y error interno.
type FailureKind string

const (
	FailNone             FailureKind = ""
	FailTransportLost    FailureKind = "transport-lost"    // pérdida de transporte
	FailAgentUnavailable FailureKind = "agent-unavailable" // agente no disponible
	FailAdminStop        FailureKind = "admin-stop"        // detención administrativa
	FailInternalError    FailureKind = "internal-error"    // error interno
)

// DefaultMaxFails es el número de fallos consecutivos que llevan a offline.
const DefaultMaxFails = 3

// Beacon representa un beacon gestionado por el manager.
type Beacon struct {
	ID          uuid.UUID
	ImplantID   *uuid.UUID // implant real asociado (adopción), nil si es lógico
	GroupID     *uuid.UUID
	Name        string
	Profile     Profile
	State       HealthState
	FailStreak  int
	MaxFails    int
	LastCheckIn time.Time
	Metadata    map[string]any
}

// BeaconGroup agrupa beacons lógicamente y define un perfil por defecto.
type BeaconGroup struct {
	ID      uuid.UUID
	Name    string
	Profile Profile
}

// Validate comprueba la configuración de un beacon.
func (b *Beacon) Validate() error {
	if b.Name == "" {
		return errors.New("beacons: name requerido")
	}
	if _, err := ParseProfile(string(b.Profile)); err != nil {
		return err
	}
	if b.MaxFails < 1 {
		return errors.New("beacons: MaxFails debe ser >= 1")
	}
	return nil
}

// newBeacon construye un beacon válido con defaults.
func newBeacon(name string, profile Profile) *Beacon {
	return &Beacon{
		ID:          uuid.New(),
		Name:        name,
		Profile:     profile,
		State:       StateOnline,
		MaxFails:    DefaultMaxFails,
		LastCheckIn: time.Now().UTC(),
		Metadata:    map[string]any{},
	}
}
