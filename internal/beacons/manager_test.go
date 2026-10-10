package beacons

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
)

type nopRecorder struct{}

func (nopRecorder) Record(ctx context.Context, beaconID uuid.UUID, kind FailureKind, detail string) {
}

// TestManagerMultipleBeaconsIndependientes verifica que varios beacons
// evolucionan de forma independiente.
func TestManagerMultipleBeaconsIndependientes(t *testing.T) {
	reg := NewRegistry(nil)
	a, err := reg.Register(context.Background(), "beacon-a", "short-haul", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.Register(context.Background(), "beacon-b", "long-haul", nil)
	if err != nil {
		t.Fatal(err)
	}

	fa, _ := reg.FSM(a.ID)
	fa.RecordFailure(FailTransportLost)
	if got := fa.State(); got != StateDegraded {
		t.Fatalf("a state=%s, want degraded", got)
	}
	fb, _ := reg.FSM(b.ID)
	if got := fb.State(); got != StateOnline {
		t.Fatalf("b state=%s, want online (independiente de a)", got)
	}
}

// TestMonitorThreeFailuresIntegration: monitor con tick corto lleva un
// beacon a offline tras 3 timeouts, y un check-in lo recupera.
func TestMonitorThreeFailuresIntegration(t *testing.T) {
	reg := NewRegistry(nil)
	rec := nopRecorder{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	var offlineCalls []uuid.UUID
	m := NewMonitor(reg, rec, log, MonitorConfig{
		Timeout:   50 * time.Millisecond,
		TickEvery: 20 * time.Millisecond,
		OnOffline: func(id uuid.UUID) { offlineCalls = append(offlineCalls, id) },
	})

	b, err := reg.Register(context.Background(), "mon", "short-haul", nil)
	if err != nil {
		t.Fatal(err)
	}
	b.LastCheckIn = time.Now().Add(-time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	defer cancel()
	defer m.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f, ok := reg.FSM(b.ID); ok && f.State() == StateOffline {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if f, _ := reg.FSM(b.ID); f.State() != StateOffline {
		t.Fatalf("estado tras timeouts = %s, want offline", f.State())
	}
	if len(offlineCalls) == 0 {
		t.Fatal("OnOffline no invocado")
	}

	m.CheckIn(b.ID)
	if f, _ := reg.FSM(b.ID); f.State() != StateOnline {
		t.Fatalf("tras recuperación state=%s, want online", f.State())
	}
	if f, _ := reg.FSM(b.ID); f.FailStreak() != 0 {
		t.Fatalf("racha tras recuperación = %d, want 0", f.FailStreak())
	}
}

// TestManagerAssignRejectsLongHaulIntegration: la política se aplica a
// través del manager.
func TestManagerAssignRejectsLongHaulIntegration(t *testing.T) {
	reg := NewRegistry(nil)
	b, err := reg.Register(context.Background(), "lh", "long-haul", nil)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Registry: reg, log: slog.Default()}
	if err := m.Assign(b.ID, PayloadBOF); err == nil {
		t.Fatal("manager aceptó BOF en long-haul")
	}
	if err := m.Assign(b.ID, PayloadHVNC); err == nil {
		t.Fatal("manager aceptó hVNC en long-haul")
	}
}

// TestManagerTunnelRequiresShortHaul: abrir túnel hVNC en long-haul falla.
func TestManagerTunnelRequiresShortHaul(t *testing.T) {
	reg := NewRegistry(nil)
	lh, _ := reg.Register(context.Background(), "lh", "long-haul", nil)
	sh, _ := reg.Register(context.Background(), "sh", "short-haul", nil)
	m := &Manager{Registry: reg, log: slog.Default(), tunnels: map[uuid.UUID]TunnelState{}}

	if err := m.OpenTunnel(lh.ID); err == nil {
		t.Fatal("túnel abierto en long-haul")
	}
	if err := m.OpenTunnel(sh.ID); err != nil {
		t.Fatalf("túnel rechazado en short-haul: %v", err)
	}
	if m.TunnelState(sh.ID) != TunnelActive {
		t.Fatalf("estado túnel = %s, want active", m.TunnelState(sh.ID))
	}
}
