package events

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// Topic identifica un canal lógico del bus.
type Topic string

const (
	// TopicImplantCheckin se publica cuando un implante hace check-in.
	// Payload: uuid.UUID del implante.
	TopicImplantCheckin Topic = "implant.checkin"

	// TopicImplantDead se publica cuando un implante se marca como muerto.
	// Payload: uuid.UUID del implante.
	TopicImplantDead Topic = "implant.dead"

	// TopicTaskCreated se publica cuando se encola una nueva tarea.
	// Payload: *models.Task.
	TopicTaskCreated Topic = "task.created"

	// TopicTaskCompleted se publica cuando una tarea termina.
	// Payload: map[string]any con task_id, implant_id, status, output, error.
	TopicTaskCompleted Topic = "task.completed"

	// TopicListenerEvent se publica cuando un listener arranca o se detiene.
	// Payload: map[string]any con id, name, type, action.
	TopicListenerEvent Topic = "listener.event"

	// TopicOperatorAction se publica cuando un operador realiza una acción.
	// Payload: map[string]any con operator_id, action, details.
	TopicOperatorAction Topic = "operator.action"
)

// Event es el mensaje que circula por el bus.
type Event struct {
	Topic   Topic
	Payload any
}

// Handler procesa un evento. Se invoca en una goroutine propia del bus,
// así que puede bloquear sin afectar al dispatcher global.
type Handler func(ctx context.Context, ev Event)

// Bus es un pub/sub in-process con suscripción por topic.
//
// Es seguro para uso concurrente.
type Bus struct {
	mu      sync.RWMutex
	topics  map[Topic]map[uuid.UUID]*subscription
	queue   chan Event
	workers int
}

type subscription struct {
	id      uuid.UUID
	handler Handler
	ch      chan Event
}

// NewBus crea un bus con N workers de despacho y una cola de tamaño queueSize.
func NewBus(workers, queueSize int) *Bus {
	if workers <= 0 {
		workers = 1
	}
	if queueSize <= 0 {
		queueSize = 1024
	}
	return &Bus{
		topics:  make(map[Topic]map[uuid.UUID]*subscription),
		queue:   make(chan Event, queueSize),
		workers: workers,
	}
}

// Start arranca los workers de despacho. Debe llamarse una sola vez.
func (b *Bus) Start(ctx context.Context) {
	for i := 0; i < b.workers; i++ {
		go b.worker(ctx)
	}
}

func (b *Bus) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-b.queue:
			b.dispatch(ctx, ev)
		}
	}
}

// dispatch entrega el evento a todos los suscriptores del topic.
func (b *Bus) dispatch(ctx context.Context, ev Event) {
	b.mu.RLock()
	subs := b.topics[ev.Topic]
	handlers := make([]*subscription, 0, len(subs))
	for _, s := range subs {
		handlers = append(handlers, s)
	}
	b.mu.RUnlock()

	for _, s := range handlers {
		select {
		case s.ch <- ev:
		default:
			// El suscriptor va lento: descartamos para no bloquear
			// a los demás suscriptores. En producción, aquí se podría
			// loggear un warning o incrementar una métrica.
		}
	}
}

// Publish publica un evento. Bloquea si la cola interna está llena,
// hasta que se libere espacio o se cancele ctx.
func (b *Bus) Publish(ctx context.Context, ev Event) {
	select {
	case b.queue <- ev:
	case <-ctx.Done():
	}
}

// Subscribe registra un handler para un topic y devuelve una función
// para cancelar la suscripción.
func (b *Bus) Subscribe(topic Topic, h Handler) func() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.topics[topic]; !ok {
		b.topics[topic] = make(map[uuid.UUID]*subscription)
	}
	id := uuid.New()
	s := &subscription{
		id:      id,
		handler: h,
		ch:      make(chan Event, 64),
	}
	b.topics[topic][id] = s

	// Goroutine que bombea del canal propio al handler.
	go func() {
		for ev := range s.ch {
			s.handler(context.Background(), ev)
		}
	}()

	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if m, ok := b.topics[topic]; ok {
			if sub, ok := m[id]; ok {
				close(sub.ch)
				delete(m, id)
			}
			if len(m) == 0 {
				delete(b.topics, topic)
			}
		}
	}
}

// SubscriberCount devuelve el número de suscriptores de un topic.
// Útil para diagnóstico.
func (b *Bus) SubscriberCount(topic Topic) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.topics[topic])
}
