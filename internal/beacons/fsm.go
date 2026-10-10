package beacons

import (
	"errors"
	"sync"
	"time"
)

// FSM es la máquina de estados de UN beacon. Cada beacon tiene su propia
// FSM con mutex propio para no bloquear a los demás bajo concurrencia.
//
// Transiciones por fallos:
//
//	online --(1 fallo)--> degraded --(MaxFails-1 fallos más)--> offline
//
// Recuperación: cualquier check-in válido resetea la racha y vuelve a online.
// admin-stop e internal-err son estados controlados, no alcanzados por fallos.
type FSM struct {
	mu         sync.RWMutex
	state      HealthState
	failStreak int
	maxFails   int
}

// NewFSM crea una FSM en estado online con el umbral de fallos dado.
func NewFSM(maxFails int) *FSM {
	if maxFails < 1 {
		maxFails = DefaultMaxFails
	}
	return &FSM{state: StateOnline, maxFails: maxFails}
}

// State devuelve el estado actual.
func (f *FSM) State() HealthState {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.state
}

// FailStreak devuelve la racha de fallos actual.
func (f *FSM) FailStreak() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.failStreak
}

// MaxFails devuelve el umbral configurado.
func (f *FSM) MaxFails() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.maxFails
}

// RecordSuccess procesa un check-in válido: resetea racha y vuelve a online.
func (f *FSM) RecordSuccess() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failStreak = 0
	if f.state == StateDegraded || f.state == StateOffline {
		f.state = StateOnline
	}
}

// RecordFailure procesa un fallo. Devuelve el nuevo estado y si el fallo
// causó la transición a offline. No afecta a estados terminales controlados
// (admin-stop, internal-err) salvo que kind sea explícitamente admin/internal.
func (f *FSM) RecordFailure(kind FailureKind) (HealthState, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch kind {
	case FailAdminStop:
		f.state = StateAdminStop
		return f.state, false
	case FailInternalError:
		f.state = StateInternalErr
		return f.state, false
	case FailNone:
		return f.state, false
	}

	// transport-lost / agent-unavailable: solo si no estamos en estado
	// terminal controlado.
	if f.state == StateAdminStop || f.state == StateInternalErr {
		return f.state, false
	}

	f.failStreak++
	if f.failStreak >= f.maxFails {
		f.state = StateOffline
		return f.state, true
	}
	if f.state == StateOnline {
		f.state = StateDegraded
	}
	return f.state, false
}

// AdminStop fuerza la detención administrativa.
func (f *FSM) AdminStop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = StateAdminStop
}

// AdminStart reactiva un beacon detenido administrativamente.
func (f *FSM) AdminStart() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == StateAdminStop {
		f.state = StateOnline
		f.failStreak = 0
	}
}

// InternalError marca un error interno (terminal controlado).
func (f *FSM) InternalError() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = StateInternalErr
}

// SinceLastCheckIn ayuda al monitor a decidir si hubo fallo por timeout.
func SinceLastCheckIn(last time.Time, timeout time.Duration) FailureKind {
	if time.Since(last) > timeout {
		return FailTransportLost
	}
	return FailNone
}

// ErrInvalidTransition se devuelve ante transiciones no permitidas.
var ErrInvalidTransition = errors.New("beacons: transición de estado inválida")
