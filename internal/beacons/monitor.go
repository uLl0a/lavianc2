package beacons

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// EventRecorder registra eventos auditableslos del manager. Es una interfaz
// pequeña para no acoplar el monitor al bus ni a SQL directamente.
type EventRecorder interface {
	Record(ctx context.Context, beaconID uuid.UUID, kind FailureKind, detail string)
}

// StatePersister persiste la transición de estado de un beacon. Interfaz
// pequeña para no acoplar el monitor al store concreto.
type StatePersister interface {
	SetState(ctx context.Context, id uuid.UUID, state HealthState, failStreak int) error
}

// Monitor observa los check-ins de los beacons y aplica la política de
// fallos consecutivos. Se alimenta de eventos de check-in (del bus) y de un
// ticker de timeout por beacon.
type Monitor struct {
	reg        *Registry
	rec        EventRecorder
	pers       StatePersister
	log        *slog.Logger
	timeout    time.Duration
	tickEvery  time.Duration
	onOffline  func(id uuid.UUID) // callback p.ej. publicar TopicImplantDead
	cancel     context.CancelFunc
}

// MonitorConfig parametriza el monitor.
type MonitorConfig struct {
	// Timeout es el tiempo sin check-in que cuenta como un fallo.
	Timeout time.Duration
	// TickEvery es la frecuencia del barrido de timeouts.
	TickEvery time.Duration
	// OnOffline se invoca cuando un beacon pasa a offline.
	OnOffline func(id uuid.UUID)
}

// NewMonitor crea un monitor. timeout por defecto 90s, tick 15s.
func NewMonitor(reg *Registry, rec EventRecorder, log *slog.Logger, cfg MonitorConfig) *Monitor {
	return NewMonitorWithPersister(reg, rec, nil, log, cfg)
}

// NewMonitorWithPersister crea un monitor que además persiste las
// transiciones de estado vía pers (puede ser nil → solo memoria).
func NewMonitorWithPersister(reg *Registry, rec EventRecorder, pers StatePersister, log *slog.Logger, cfg MonitorConfig) *Monitor {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}
	if cfg.TickEvery <= 0 {
		cfg.TickEvery = 15 * time.Second
	}
	return &Monitor{
		reg:       reg,
		rec:       rec,
		pers:      pers,
		log:       log,
		timeout:   cfg.Timeout,
		tickEvery: cfg.TickEvery,
		onOffline: cfg.OnOffline,
	}
}

// CheckIn notifica un check-in válido de un beacon al monitor.
func (m *Monitor) CheckIn(id uuid.UUID) {
	m.reg.TouchCheckIn(id)
}

// Start lanza el bucle de barrido. Se detiene con el ctx o con Stop().
func (m *Monitor) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	go m.loop(ctx)
}

// Stop detiene el monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *Monitor) loop(ctx context.Context) {
	t := time.NewTicker(m.tickEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sweep(ctx)
		}
	}
}

// sweep recorre los beacons y registra fallos por timeout.
func (m *Monitor) sweep(ctx context.Context) {
	now := time.Now()
	for _, b := range m.reg.List() {
		f, ok := m.reg.FSM(b.ID)
		if !ok {
			continue
		}
		st := f.State()
		if st == StateAdminStop || st == StateInternalErr || st == StateOffline {
			continue
		}
		if now.Sub(b.LastCheckIn) <= m.timeout {
			continue
		}
		kind := SinceLastCheckIn(b.LastCheckIn, m.timeout)
		newState, wentOffline := f.RecordFailure(kind)
		// Reflejar en el objeto Beacon en memoria.
		b.State = newState
		b.FailStreak = f.FailStreak()
		// Persistir la transición para que sobreviva y sea consultable.
		if m.pers != nil {
			if err := m.pers.SetState(ctx, b.ID, newState, f.FailStreak()); err != nil {
				m.log.Warn("monitor: persistir estado", "beacon", b.ID, "err", err)
			}
		}
		m.rec.Record(ctx, b.ID, kind,
			"timeout de check-in; racha="+itoa(f.FailStreak()))
		if wentOffline && m.onOffline != nil {
			m.onOffline(b.ID)
		}
		m.log.Debug("monitor: fallo registrado",
			"beacon", b.ID, "state", string(newState), "kind", string(kind))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
