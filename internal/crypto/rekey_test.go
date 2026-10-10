package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// newKeyPair genera un par X25519 o falla el test.
func newKeyPair(t *testing.T) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return priv, pub
}

// TestSessionCryptoRoundtrip verifica el caso base: server e implante
// derivan las mismas claves desde ECDH y pueden cifrar/descifrar en ambas
// direcciones.
func TestSessionCryptoRoundtrip(t *testing.T) {
	serverPriv, _ := newKeyPair(t)
	implantPriv, _ := newKeyPair(t)

	const sessionKey = "testsession1234"

	serverSc, err := NewSessionCrypto(serverPriv, implantPriv.PublicKey(), sessionKey, 5)
	if err != nil {
		t.Fatalf("NewSessionCrypto: %v", err)
	}
	implantSc, err := NewSessionCryptoAsBeacon(implantPriv, serverPriv.PublicKey(), sessionKey, 5)
	if err != nil {
		t.Fatalf("NewSessionCryptoAsBeacon: %v", err)
	}

	// C2 -> beacon
	msg := []byte("hola desde el team server")
	enc, err := serverSc.EncryptForBeacon(msg, nil)
	if err != nil {
		t.Fatalf("EncryptForBeacon: %v", err)
	}
	dec, err := implantSc.DecryptFromC2(enc, nil)
	if err != nil {
		t.Fatalf("DecryptFromC2: %v", err)
	}
	if !bytes.Equal(msg, dec) {
		t.Fatalf("c2->beacon: got %q want %q", dec, msg)
	}

	// beacon -> C2
	msg2 := []byte("hola desde el implante")
	enc2, err := implantSc.EncryptForC2(msg2, nil)
	if err != nil {
		t.Fatalf("EncryptForC2: %v", err)
	}
	dec2, err := serverSc.DecryptFromBeacon(enc2, nil)
	if err != nil {
		t.Fatalf("DecryptFromBeacon: %v", err)
	}
	if !bytes.Equal(msg2, dec2) {
		t.Fatalf("beacon->c2: got %q want %q", dec2, msg2)
	}
}

// TestSessionCryptoRekeyFlow simula el flujo bilateral completo del rekey
// tal como lo ejecutan los listeners (server) y el template (implante):
//
//  1. Server genera par efímero y envía server_eph_pub cifrado con claves
//     viejas (MsgKeyRotation).
//  2. Implante genera su par efímero, responde implant_eph_pub cifrado
//     con claves VIEJAS.
//  3. Ambos aplican ApplyRekey* con ECDH efímero.
//  4. Server responde ack "ok" cifrado con claves NUEVAS.
//  5. Ambos lados siguen comunicándose con las claves nuevas.
//
// El contador se fuerza a rekeyEvery=5 (tarea del roadmap: validar el
// rekey escrito pero nunca ejecutado).
func TestSessionCryptoRekeyFlow(t *testing.T) {
	serverPriv, _ := newKeyPair(t)
	implantPriv, _ := newKeyPair(t)

	const sessionKey = "rekeytest00001"

	serverSc, err := NewSessionCrypto(serverPriv, implantPriv.PublicKey(), sessionKey, 5)
	if err != nil {
		t.Fatalf("NewSessionCrypto: %v", err)
	}
	implantSc, err := NewSessionCryptoAsBeacon(implantPriv, serverPriv.PublicKey(), sessionKey, 5)
	if err != nil {
		t.Fatalf("NewSessionCryptoAsBeacon: %v", err)
	}

	// Simular rekeyEvery=5: intercambios previos a la rotación.
	const rekeyEvery = 5
	for i := 0; i < rekeyEvery; i++ {
		serverSc.IncrementMsg()
		implantSc.IncrementMsg()
	}
	if !serverSc.ShouldRekey() {
		t.Fatalf("ShouldRekey debería ser true tras %d mensajes", rekeyEvery)
	}

	// Paso 1: server genera efímero y envía server_eph_pub (claves viejas).
	serverEphPriv, serverEphPub := newKeyPair(t)
	rotReq := map[string]string{
		"server_eph_pub": base64.StdEncoding.EncodeToString(serverEphPub.Bytes()),
	}
	rotJSON, err := json.Marshal(rotReq)
	if err != nil {
		t.Fatalf("marshal rotación: %v", err)
	}
	encRot, err := serverSc.EncryptForBeacon(rotJSON, nil)
	if err != nil {
		t.Fatalf("EncryptForBeacon rotación: %v", err)
	}

	// Paso 2: implante descifra con claves viejas, genera efímero y
	// responde con claves VIEJAS.
	plain, err := implantSc.DecryptFromC2(encRot, nil)
	if err != nil {
		t.Fatalf("implante no pudo descifrar rotación: %v", err)
	}
	var rotReqParsed struct {
		ServerEphPub string `json:"server_eph_pub"`
	}
	if err := json.Unmarshal(plain, &rotReqParsed); err != nil {
		t.Fatalf("unmarshal rotación: %v", err)
	}
	serverEphPubBytes, err := base64.StdEncoding.DecodeString(rotReqParsed.ServerEphPub)
	if err != nil {
		t.Fatalf("decode server_eph_pub: %v", err)
	}
	if len(serverEphPubBytes) == 0 {
		t.Fatal("server_eph_pub vacío")
	}

	implantEphPriv, implantEphPub := newKeyPair(t)
	resp := map[string]string{
		"implant_eph_pub": base64.StdEncoding.EncodeToString(implantEphPub.Bytes()),
	}
	respJSON, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal respuesta: %v", err)
	}
	encResp, err := implantSc.EncryptForC2(respJSON, nil)
	if err != nil {
		t.Fatalf("EncryptForC2 respuesta: %v", err)
	}

	// Paso 3a: server descifra la respuesta (claves viejas) y aplica rekey.
	respPlain, err := serverSc.DecryptFromBeacon(encResp, nil)
	if err != nil {
		t.Fatalf("server no pudo descifrar respuesta del implante: %v", err)
	}
	var respParsed struct {
		ImplantEphPub string `json:"implant_eph_pub"`
	}
	if err := json.Unmarshal(respPlain, &respParsed); err != nil {
		t.Fatalf("unmarshal respuesta implante: %v", err)
	}
	implantEphPubBytes, err := base64.StdEncoding.DecodeString(respParsed.ImplantEphPub)
	if err != nil {
		t.Fatalf("decode implant_eph_pub: %v", err)
	}
	implantEphPubParsed, err := PublicKeyFromBytes(implantEphPubBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes implant eph: %v", err)
	}
	if err := serverSc.ApplyRekeyAsServer(serverEphPriv, implantEphPubParsed); err != nil {
		t.Fatalf("ApplyRekeyAsServer: %v", err)
	}

	// Paso 3b: implante aplica rekey con su ephPriv y la ephPub del server.
	serverEphPubParsed, err := PublicKeyFromBytes(serverEphPubBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes server eph: %v", err)
	}
	if err := implantSc.ApplyRekeyAsBeacon(implantEphPriv, serverEphPubParsed); err != nil {
		t.Fatalf("ApplyRekeyAsBeacon: %v", err)
	}

	// Paso 4: server envía ack con claves NUEVAS; implante lo descifra.
	ack, err := serverSc.EncryptForBeacon([]byte("ok"), nil)
	if err != nil {
		t.Fatalf("EncryptForBeacon ack: %v", err)
	}
	ackPlain, err := implantSc.DecryptFromC2(ack, nil)
	if err != nil {
		t.Fatalf("descifrar ack con claves nuevas falló: %v", err)
	}
	if string(ackPlain) != "ok" {
		t.Fatalf("ack inesperado: %q", ackPlain)
	}

	// Paso 5: la sesión sigue viva en ambas direcciones tras el rekey.
	for i := 0; i < 3; i++ {
		outMsg := []byte("mensaje post-rekey del C2")
		enc, err := serverSc.EncryptForBeacon(outMsg, nil)
		if err != nil {
			t.Fatalf("post-rekey EncryptForBeacon: %v", err)
		}
		dec, err := implantSc.DecryptFromC2(enc, nil)
		if err != nil {
			t.Fatalf("post-rekey DecryptFromC2 falló (claves desincronizadas): %v", err)
		}
		if !bytes.Equal(outMsg, dec) {
			t.Fatalf("post-rekey payload corrupto: got %q want %q", dec, outMsg)
		}

		inMsg := []byte("resultado post-rekey del implante")
		enc2, err := implantSc.EncryptForC2(inMsg, nil)
		if err != nil {
			t.Fatalf("post-rekey EncryptForC2: %v", err)
		}
		dec2, err := serverSc.DecryptFromBeacon(enc2, nil)
		if err != nil {
			t.Fatalf("post-rekey DecryptFromBeacon falló (claves desincronizadas): %v", err)
		}
		if !bytes.Equal(inMsg, dec2) {
			t.Fatalf("post-rekey payload corrupto: got %q want %q", dec2, inMsg)
		}
	}

	// El contador debe resetearse tras el rekey.
	if serverSc.ShouldRekey() {
		t.Fatal("ShouldRekey debe ser false justo tras el rekey")
	}
	if serverSc.MsgCount() != 0 {
		t.Fatalf("msgCount debe resetear a 0, got %d", serverSc.MsgCount())
	}
}

// TestRekeyClavesDistintas verifica que tras el rekey las claves nuevas
// son distintas de las viejas.
func TestRekeyClavesDistintas(t *testing.T) {
	serverPriv, _ := newKeyPair(t)
	implantPriv, _ := newKeyPair(t)

	serverSc, err := NewSessionCrypto(serverPriv, implantPriv.PublicKey(), "distintas12345", DefaultRekeyEvery)
	if err != nil {
		t.Fatalf("NewSessionCrypto: %v", err)
	}
	implantSc, err := NewSessionCryptoAsBeacon(implantPriv, serverPriv.PublicKey(), "distintas12345", DefaultRekeyEvery)
	if err != nil {
		t.Fatalf("NewSessionCryptoAsBeacon: %v", err)
	}

	oldC2, oldBC, _, _ := serverSc.Keys()

	serverEphPriv, serverEphPub := newKeyPair(t)
	implantEphPriv, implantEphPub := newKeyPair(t)

	if err := serverSc.ApplyRekeyAsServer(serverEphPriv, implantEphPub); err != nil {
		t.Fatalf("ApplyRekeyAsServer: %v", err)
	}
	if err := implantSc.ApplyRekeyAsBeacon(implantEphPriv, serverEphPub); err != nil {
		t.Fatalf("ApplyRekeyAsBeacon: %v", err)
	}

	newC2, newBC, _, _ := serverSc.Keys()
	if bytes.Equal(oldC2, newC2) {
		t.Fatal("c2ToBeacon no cambió tras el rekey")
	}
	if bytes.Equal(oldBC, newBC) {
		t.Fatal("beaconToC2 no cambió tras el rekey")
	}
}

// TestRekeyPersistencia verifica el round-trip por claves persistidas:
// claves derivadas → persistidas (Keys()) → recargadas
// (NewSessionCryptoFromKeys) → rekey posterior OK y sincronizado con el
// implante.
func TestRekeyPersistencia(t *testing.T) {
	serverPriv, _ := newKeyPair(t)
	implantPriv, _ := newKeyPair(t)

	serverSc, err := NewSessionCrypto(serverPriv, implantPriv.PublicKey(), "persist01", DefaultRekeyEvery)
	if err != nil {
		t.Fatalf("NewSessionCrypto: %v", err)
	}
	c2, bc, msgCount, rekeyEvery := serverSc.Keys()

	// Simular recarga desde DB (NewSessionCryptoFromKeys).
	reloaded, err := NewSessionCryptoFromKeys(c2, bc, msgCount, rekeyEvery)
	if err != nil {
		t.Fatalf("NewSessionCryptoFromKeys: %v", err)
	}

	// El reloaded debe poder rekeyar igual (info strings fijos del rekey).
	serverEphPriv, serverEphPub := newKeyPair(t)
	implantEphPriv, implantEphPub := newKeyPair(t)
	if err := reloaded.ApplyRekeyAsServer(serverEphPriv, implantEphPub); err != nil {
		t.Fatalf("reloaded ApplyRekeyAsServer: %v", err)
	}

	// El beacon (que nunca se recargó) aplica el mismo rekey y ambos
	// quedan sincronizados.
	implantSc, err := NewSessionCryptoAsBeacon(implantPriv, serverPriv.PublicKey(), "persist01", DefaultRekeyEvery)
	if err != nil {
		t.Fatalf("NewSessionCryptoAsBeacon: %v", err)
	}
	if err := implantSc.ApplyRekeyAsBeacon(implantEphPriv, serverEphPub); err != nil {
		t.Fatalf("ApplyRekeyAsBeacon: %v", err)
	}

	enc, err := reloaded.EncryptForBeacon([]byte("sync tras reload+rekey"), nil)
	if err != nil {
		t.Fatalf("EncryptForBeacon: %v", err)
	}
	if _, err := implantSc.DecryptFromC2(enc, nil); err != nil {
		t.Fatalf("implante no pudo descifrar tras reload+rekey: %v", err)
	}
}