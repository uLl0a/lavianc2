package beacons

import (
	"sync"
	"testing"
)

func TestFSMOnlineStarts(t *testing.T) {
	f := NewFSM(DefaultMaxFails)
	if f.State() != StateOnline {
		t.Fatalf("estado inicial = %s, want online", f.State())
	}
	if f.MaxFails() != DefaultMaxFails {
		t.Fatalf("maxFails = %d, want %d", f.MaxFails(), DefaultMaxFails)
	}
}

func TestFSMThreeConsecutiveFailuresGoOffline(t *testing.T) {
	f := NewFSM(3) // escenario configurable: 3 fallos consecutivos

	// Fallo 1 → degraded
	st, off := f.RecordFailure(FailTransportLost)
	if off || st != StateDegraded {
		t.Fatalf("tras 1 fallo: state=%s offline=%v, want degraded/false", st, off)
	}

	// Fallo 2 → sigue degraded
	st, off = f.RecordFailure(FailAgentUnavailable)
	if off || st != StateDegraded {
		t.Fatalf("tras 2 fallos: state=%s offline=%v, want degraded/false", st, off)
	}

	// Fallo 3 → offline
	st, off = f.RecordFailure(FailTransportLost)
	if !off || st != StateOffline {
		t.Fatalf("tras 3 fallos: state=%s offline=%v, want offline/true", st, off)
	}
}

func TestFSMRecoveryResetsStreak(t *testing.T) {
	f := NewFSM(3)
	f.RecordFailure(FailTransportLost)
	f.RecordFailure(FailTransportLost)
	if f.FailStreak() != 2 {
		t.Fatalf("racha = %d, want 2", f.FailStreak())
	}

	// Un check-in válido recupera y resetea
	f.RecordSuccess()
	if f.State() != StateOnline {
		t.Fatalf("tras recuperación state=%s, want online", f.State())
	}
	if f.FailStreak() != 0 {
		t.Fatalf("racha tras recuperación = %d, want 0", f.FailStreak())
	}

	// Ahora necesita otros 3 fallos para ir offline (la racha se reseteó)
	f.RecordFailure(FailTransportLost)
	f.RecordFailure(FailTransportLost)
	st, off := f.RecordFailure(FailTransportLost)
	if !off || st != StateOffline {
		t.Fatalf("tras re-recuperación, 3 fallos: state=%s offline=%v", st, off)
	}
}

func TestFSMAdminStopIsTerminalForFailures(t *testing.T) {
	f := NewFSM(3)
	f.AdminStop()
	if f.State() != StateAdminStop {
		t.Fatalf("state=%s, want admin-stop", f.State())
	}
	// Los fallos por timeout no cambian admin-stop
	st, _ := f.RecordFailure(FailTransportLost)
	if st != StateAdminStop {
		t.Fatalf("fallo durante admin-stop cambió state a %s", st)
	}
}

func TestFSMAdminStartReactivates(t *testing.T) {
	f := NewFSM(3)
	f.AdminStop()
	f.AdminStart()
	if f.State() != StateOnline {
		t.Fatalf("tras AdminStart state=%s, want online", f.State())
	}
	if f.FailStreak() != 0 {
		t.Fatalf("racha tras AdminStart = %d, want 0", f.FailStreak())
	}
}

func TestFSMInternalErrorKind(t *testing.T) {
	f := NewFSM(3)
	st, _ := f.RecordFailure(FailInternalError)
	if st != StateInternalErr {
		t.Fatalf("fail internal-error state=%s, want internal-err", st)
	}
}

func TestFSMConcurrency(t *testing.T) {
	f := NewFSM(3)
	var wg sync.WaitGroup
	// N goroutines registran fallos y éxitos concurrentemente.
	// No debe haber race ni panic; la FSM debe seguir siendo consistente.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if (n+j)%3 == 0 {
					f.RecordSuccess()
				} else {
					f.RecordFailure(FailTransportLost)
				}
			}
		}(i)
	}
	wg.Wait()
	// El estado final debe ser uno de los válidos.
	s := f.State()
	switch s {
	case StateOnline, StateDegraded, StateOffline, StateAdminStop, StateInternalErr:
		// ok
	default:
		t.Fatalf("estado inválido tras concurrencia: %s", s)
	}
}

func TestParseProfile(t *testing.T) {
	if _, err := ParseProfile("short-haul"); err != nil {
		t.Fatalf("short-haul válido rechazado: %v", err)
	}
	if _, err := ParseProfile("long-haul"); err != nil {
		t.Fatalf("long-haul válido rechazado: %v", err)
	}
	if _, err := ParseProfile("bogus"); err == nil {
		t.Fatal("perfil inválido aceptado")
	}
	if _, err := ParseProfile(""); err == nil {
		t.Fatal("perfil vacío aceptado")
	}
}

func TestValidateRejectsBadMaxFails(t *testing.T) {
	b := newBeacon("test", ProfileShortHaul)
	b.MaxFails = 0
	if err := b.Validate(); err == nil {
		t.Fatal("MaxFails=0 no rechazado")
	}
	b.MaxFails = -5
	if err := b.Validate(); err == nil {
		t.Fatal("MaxFails<0 no rechazado")
	}
}
