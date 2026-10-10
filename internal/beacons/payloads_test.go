package beacons

import "testing"

// La REGLA DURA: BOF/.NET/hVNC solo a short-haul. Long-Haul los rechaza.
func TestAssignPayloadRejectsLongHaul(t *testing.T) {
	for _, kind := range []PayloadKind{PayloadBOF, PayloadAssembly, PayloadHVNC} {
		b := newBeacon("lh", ProfileLongHaul)
		if err := AssignPayload(b, kind); err == nil {
			t.Fatalf("%s aceptado en long-haul (debe rechazarse)", kind)
		}
	}
}

func TestAssignPayloadAcceptsShortHaul(t *testing.T) {
	for _, kind := range []PayloadKind{PayloadBOF, PayloadAssembly, PayloadHVNC} {
		b := newBeacon("sh", ProfileShortHaul)
		if err := AssignPayload(b, kind); err != nil {
			t.Fatalf("%s rechazado en short-haul: %v", kind, err)
		}
	}
}

func TestAssignPayloadRejectsUnavailableBeacon(t *testing.T) {
	b := newBeacon("sh", ProfileShortHaul)
	b.State = StateOffline
	if err := AssignPayload(b, PayloadBOF); err == nil {
		t.Fatal("BOF aceptado en beacon offline")
	}
	b.State = StateAdminStop
	if err := AssignPayload(b, PayloadBOF); err == nil {
		t.Fatal("BOF aceptado en beacon admin-stop")
	}
}

func TestAssignPayloadRejectsInvalidKind(t *testing.T) {
	b := newBeacon("sh", ProfileShortHaul)
	if err := AssignPayload(b, "bogus"); err == nil {
		t.Fatal("kind inválido aceptado")
	}
	if err := AssignPayload(nil, PayloadBOF); err == nil {
		t.Fatal("beacon nil aceptado")
	}
}

func TestParsePayloadKind(t *testing.T) {
	for _, k := range []string{"bof", "assembly", "hvnc"} {
		if _, err := ParsePayloadKind(k); err != nil {
			t.Fatalf("%s válido rechazado: %v", k, err)
		}
	}
	if _, err := ParsePayloadKind("nope"); err == nil {
		t.Fatal("kind inválido aceptado")
	}
}
