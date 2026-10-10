package adapters

import "testing"

func TestNewRegistryMarksImplemented(t *testing.T) {
	r := NewRegistry("https-1", "dns-1", "quic-1")
	for _, p := range []Protocol{ProtoHTTPS, ProtoDNS, ProtoQUIC} {
		if !r.Implemented(p) {
			t.Fatalf("%s debería estar implementado", p)
		}
	}
	if r.Implemented(ProtoWebSocket) {
		t.Fatal("websocket no debería estar implementado aún (requiere extensión)")
	}
}

func TestRegisterUpgradeVersion(t *testing.T) {
	r := NewRegistry("", "", "")
	err := r.Register(Profile{Protocol: ProtoHTTPS, Version: 2, Implemented: true})
	if err != nil {
		t.Fatalf("upgrade de versión rechazado: %v", err)
	}
	p, _ := r.Get(ProtoHTTPS)
	if p.Version != 2 {
		t.Fatalf("versión = %d, want 2", p.Version)
	}
}

func TestRegisterRejectsDowngrade(t *testing.T) {
	r := NewRegistry("", "", "")
	err := r.Register(Profile{Protocol: ProtoHTTPS, Version: 0})
	if err == nil {
		t.Fatal("downgrade de versión aceptado")
	}
}

func TestRegisterRejectsEmptyProtocol(t *testing.T) {
	r := NewRegistry("", "", "")
	if err := r.Register(Profile{Protocol: "", Version: 1}); err == nil {
		t.Fatal("protocolo vacío aceptado")
	}
}
