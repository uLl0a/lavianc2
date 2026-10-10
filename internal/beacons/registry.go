package beacons

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// BeaconStore es la interfaz de persistencia del registry. Interfaz
// pequeña para no acoplar el manager a pgx ni a detalles SQL.
type BeaconStore interface {
	SaveGroup(ctx context.Context, g *BeaconGroup) error
	GetGroup(ctx context.Context, id uuid.UUID) (*BeaconGroup, error)
	ListGroups(ctx context.Context) ([]*BeaconGroup, error)

	Save(ctx context.Context, b *Beacon) error
	Get(ctx context.Context, id uuid.UUID) (*Beacon, error)
	List(ctx context.Context) ([]*Beacon, error)
	SetState(ctx context.Context, id uuid.UUID, state HealthState, failStreak int) error
	SetProfile(ctx context.Context, id uuid.UUID, profile Profile) error
	RecordEvent(ctx context.Context, beaconID uuid.UUID, kind FailureKind, detail string) error
}

// Registry mantiene los beacons en memoria y los persiste vía BeaconStore.
type Registry struct {
	mu      sync.RWMutex
	beacons map[uuid.UUID]*Beacon
	fsms    map[uuid.UUID]*FSM
	groups  map[uuid.UUID]*BeaconGroup
	store   BeaconStore
}

// NewRegistry crea un registry. store puede ser nil (solo memoria).
func NewRegistry(store BeaconStore) *Registry {
	return &Registry{
		beacons: make(map[uuid.UUID]*Beacon),
		fsms:    make(map[uuid.UUID]*FSM),
		groups:  make(map[uuid.UUID]*BeaconGroup),
		store:   store,
	}
}

// Adopt vincula un implant real (que acaba de hacer check-in) con un beacon
// gestionado. Si el implant ya tiene beacon asociado, lo toca (online).
// Si no, deriva el perfil del sleep_interval (alto = long-haul) y crea uno.
func (r *Registry) Adopt(implantID uuid.UUID, hostname, sessionKey string, sleepSecs int) (*Beacon, error) {
	r.mu.Lock()
	// ¿ya adoptado?
	for _, b := range r.beacons {
		if b.ImplantID != nil && *b.ImplantID == implantID {
			b.LastCheckIn = time.Now().UTC()
			f := r.fsms[b.ID]
			r.mu.Unlock()
			if f != nil {
				f.RecordSuccess()
			}
			return b, nil
		}
	}
	r.mu.Unlock()

	// Derivar perfil: sleep alto = supervivencia (long-haul).
	profile := ProfileLongHaul
	if sleepSecs > 0 && sleepSecs <= 60 {
		profile = ProfileShortHaul
	}
	name := hostname
	if name == "" {
		name = sessionKey
	}
	if name == "" {
		name = "impl-" + implantID.String()[:8]
	}

	b := newBeacon(name, profile)
	b.ImplantID = &implantID
	b.LastCheckIn = time.Now().UTC()
	if err := b.Validate(); err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.beacons[b.ID] = b
	r.fsms[b.ID] = NewFSM(b.MaxFails)
	r.mu.Unlock()

	if r.store != nil {
		// contexto background: la adopción viene de un handler del bus.
		if err := r.store.Save(context.Background(), b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// ImplantOf devuelve el ID del implant asociado a un beacon, o nil.
func (r *Registry) ImplantOf(beaconID uuid.UUID) *uuid.UUID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if b, ok := r.beacons[beaconID]; ok {
		return b.ImplantID
	}
	return nil
}

// ByImplant devuelve el beacon asociado a un implant, si existe.
func (r *Registry) ByImplant(implantID uuid.UUID) (*Beacon, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range r.beacons {
		if b.ImplantID != nil && *b.ImplantID == implantID {
			return b, true
		}
	}
	return nil, false
}

// Register crea y registra un beacon.
func (r *Registry) Register(ctx context.Context, name, profileStr string, groupID *uuid.UUID) (*Beacon, error) {
	profile, err := ParseProfile(profileStr)
	if err != nil {
		return nil, err
	}
	b := newBeacon(name, profile)
	b.GroupID = groupID
	if err := b.Validate(); err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.beacons[b.ID] = b
	r.fsms[b.ID] = NewFSM(b.MaxFails)
	r.mu.Unlock()

	if r.store != nil {
		if err := r.store.Save(ctx, b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Get devuelve un beacon por id.
func (r *Registry) Get(id uuid.UUID) (*Beacon, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.beacons[id]
	return b, ok
}

// FSM devuelve la FSM asociada a un beacon.
func (r *Registry) FSM(id uuid.UUID) (*FSM, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.fsms[id]
	return f, ok
}

// ListGroups devuelve los grupos desde memoria (o store si no hay en memoria).
func (r *Registry) ListGroups(ctx context.Context) ([]*BeaconGroup, error) {
	r.mu.RLock()
	out := make([]*BeaconGroup, 0, len(r.groups))
	for _, g := range r.groups {
		out = append(out, g)
	}
	r.mu.RUnlock()
	if len(out) > 0 || r.store == nil {
		return out, nil
	}
	return r.store.ListGroups(ctx)
}

// List devuelve todos los beacons.
func (r *Registry) List() []*Beacon {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Beacon, 0, len(r.beacons))
	for _, b := range r.beacons {
		out = append(out, b)
	}
	return out
}

// CreateGroup crea un grupo lógico.
func (r *Registry) CreateGroup(ctx context.Context, name, profileStr string) (*BeaconGroup, error) {
	profile, err := ParseProfile(profileStr)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("beacons: nombre de grupo requerido")
	}
	g := &BeaconGroup{ID: uuid.New(), Name: name, Profile: profile}
	r.mu.Lock()
	r.groups[g.ID] = g
	r.mu.Unlock()
	if r.store != nil {
		if err := r.store.SaveGroup(ctx, g); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// SetProfile cambia el perfil de un beacon y lo persiste.
func (r *Registry) SetProfile(ctx context.Context, id uuid.UUID, profile Profile) error {
	if _, err := ParseProfile(string(profile)); err != nil {
		return err
	}
	r.mu.Lock()
	b, ok := r.beacons[id]
	if !ok {
		r.mu.Unlock()
		return errors.New("beacons: beacon no encontrado")
	}
	b.Profile = profile
	r.mu.Unlock()
	if r.store != nil {
		return r.store.SetProfile(ctx, id, profile)
	}
	return nil
}

// TouchCheckIn actualiza LastCheckIn y la FSM tras un check-in válido.
func (r *Registry) TouchCheckIn(id uuid.UUID) {
	r.mu.Lock()
	b, ok := r.beacons[id]
	f := r.fsms[id]
	r.mu.Unlock()
	if ok {
		b.LastCheckIn = time.Now().UTC()
	}
	if f != nil {
		f.RecordSuccess()
		if ok {
			b.State = f.State()
			b.FailStreak = f.FailStreak()
		}
	}
}

var ErrNotFound = errors.New("beacons: no encontrado")
