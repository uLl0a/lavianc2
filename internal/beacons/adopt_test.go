package beacons

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// fakeLookup simula un ImplantLookup para las pruebas de adopción.
type fakeLookup struct {
	implants map[uuid.UUID]fakeImpl
}

type fakeImpl struct {
	hostname string
	session  string
	sleep    int
}

func (f fakeLookup) Get(ctx context.Context, id uuid.UUID) (implantGetter, error) {
	if imp, ok := f.implants[id]; ok {
		return fakeImplantResult{imp}, nil
	}
	return nil, nil
}

// Las interfaces pequeñas evitan acoplar el test a models.Implant.
type implantGetter interface{ vals() (string, string, int) }
type fakeImplantResult struct{ imp fakeImpl }

func (r fakeImplantResult) vals() (string, string, int) { return r.imp.hostname, r.imp.session, r.imp.sleep }

func TestAdoptCreatesBeaconFromImplant(t *testing.T) {
	reg := NewRegistry(nil)
	implantID := uuid.New()

	// sleep corto (≤60) → short-haul
	b, err := reg.Adopt(implantID, "host1", "sess1", 30)
	if err != nil {
		t.Fatal(err)
	}
	if b.Profile != ProfileShortHaul {
		t.Fatalf("perfil = %s, want short-haul (sleep 30)", b.Profile)
	}
	if b.ImplantID == nil || *b.ImplantID != implantID {
		t.Fatal("ImplantID no vinculado")
	}
	if b.Name != "host1" {
		t.Fatalf("nombre = %s, want host1", b.Name)
	}
}

func TestAdoptLongHaulForHighSleep(t *testing.T) {
	reg := NewRegistry(nil)
	b, err := reg.Adopt(uuid.New(), "host2", "sess2", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if b.Profile != ProfileLongHaul {
		t.Fatalf("perfil = %s, want long-haul (sleep 3600)", b.Profile)
	}
}

func TestAdoptIdempotent(t *testing.T) {
	reg := NewRegistry(nil)
	implantID := uuid.New()

	b1, err := reg.Adopt(implantID, "h", "s", 30)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := reg.Adopt(implantID, "h", "s", 30)
	if err != nil {
		t.Fatal(err)
	}
	if b1.ID != b2.ID {
		t.Fatalf("adopción no idempotente: %s vs %s", b1.ID, b2.ID)
	}
	if len(reg.List()) != 1 {
		t.Fatalf("beacons = %d, want 1 (no duplicar)", len(reg.List()))
	}
}

func TestByImplant(t *testing.T) {
	reg := NewRegistry(nil)
	implantID := uuid.New()
	reg.Adopt(implantID, "h", "s", 30)

	got, ok := reg.ByImplant(implantID)
	if !ok || got.ImplantID == nil || *got.ImplantID != implantID {
		t.Fatal("ByImplant no encontró el beacon adoptado")
	}
	if _, ok := reg.ByImplant(uuid.New()); ok {
		t.Fatal("ByImplant encontró un implant inexistente")
	}
}
