// Package transfers gestiona transferencias chunked de archivos entre
// implantes y el team server. Los chunks llegan como mensajes
// MsgFileChunk y se reensamblan aquí.
package transfers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/protocol"
)

// Manager mantiene el estado de las transferencias activas y las
// reensambla cuando llega el mensaje "end".
type Manager struct {
	mu        sync.RWMutex
	transfers map[string]*Transfer

	outputDir string
	bus       *events.Bus
	log       *slog.Logger
}

// Transfer representa una transferencia chunked en curso.
type Transfer struct {
	ID         string
	TaskID     string
	ImplantID  uuid.UUID
	Direction  string
	Path       string
	Name       string
	TotalSize  int64
	SHA256     string
	ChunkCount int
	StartedAt  time.Time

	mu          sync.Mutex
	chunks      map[int][]byte
	bytesRecv   int64
	CompletedAt time.Time
	Status      string
	LastError   string
}

// NewManager crea el manager y asegura que outputDir existe.
func NewManager(outputDir string, bus *events.Bus, log *slog.Logger) (*Manager, error) {
	if outputDir == "" {
		return nil, fmt.Errorf("transfers: outputDir requerido")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("transfers: crear output dir: %w", err)
	}
	return &Manager{
		transfers: make(map[string]*Transfer),
		outputDir: outputDir,
		bus:       bus,
		log:       log,
	}, nil
}

// Handle procesa un FileTransferWire y actualiza el estado de la
// transferencia correspondiente.
func (m *Manager) Handle(ctx context.Context, wire *protocol.FileTransferWire, implantID uuid.UUID) error {
	switch wire.Kind {
	case "start":
		return m.handleStart(ctx, wire, implantID)
	case "chunk":
		return m.handleChunk(ctx, wire)
	case "end":
		return m.handleEnd(ctx, wire)
	default:
		return fmt.Errorf("transfers: kind desconocido %q", wire.Kind)
	}
}

func (m *Manager) handleStart(ctx context.Context, wire *protocol.FileTransferWire, implantID uuid.UUID) error {
	if wire.TransferID == "" {
		return fmt.Errorf("transfers: transfer_id requerido en start")
	}
	if wire.ChunkCount <= 0 {
		return fmt.Errorf("transfers: chunk_count inválido: %d", wire.ChunkCount)
	}

	t := &Transfer{
		ID:         wire.TransferID,
		TaskID:     wire.TaskID,
		ImplantID:  implantID,
		Direction:  wire.Direction,
		Path:       wire.Path,
		Name:       wire.Name,
		TotalSize:  wire.TotalSize,
		SHA256:     wire.SHA256,
		ChunkCount: wire.ChunkCount,
		StartedAt:  time.Now().UTC(),
		chunks:     make(map[int][]byte),
		Status:     "in_progress",
	}

	m.mu.Lock()
	m.transfers[wire.TransferID] = t
	m.mu.Unlock()

	m.log.Info("transfer: iniciado",
		"id", wire.TransferID,
		"task", wire.TaskID,
		"implant", implantID,
		"name", wire.Name,
		"size", wire.TotalSize,
		"chunks", wire.ChunkCount,
	)
	m.bus.Publish(ctx, events.Event{
		Topic: events.TopicOperatorAction,
		Payload: map[string]any{
			"action":   "file.transfer.start",
			"transfer": wire.TransferID,
			"implant":  implantID.String(),
			"name":     wire.Name,
			"size":     wire.TotalSize,
		},
	})
	return nil
}

func (m *Manager) handleChunk(ctx context.Context, wire *protocol.FileTransferWire) error {
	m.mu.RLock()
	t, ok := m.transfers[wire.TransferID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("transfers: transfer %s no encontrado", wire.TransferID)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.chunks[wire.Index]; exists {
		// Idempotente: un chunk repetido se ignora.
		return nil
	}
	t.chunks[wire.Index] = wire.Data
	t.bytesRecv += int64(len(wire.Data))

	m.log.Debug("transfer: chunk",
		"id", wire.TransferID,
		"index", wire.Index,
		"size", len(wire.Data),
		"total_recv", t.bytesRecv,
	)
	return nil
}

func (m *Manager) handleEnd(ctx context.Context, wire *protocol.FileTransferWire) error {
	m.mu.Lock()
	t, ok := m.transfers[wire.TransferID]
	if ok {
		delete(m.transfers, wire.TransferID)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("transfers: transfer %s no encontrado", wire.TransferID)
	}

	if !wire.OK {
		t.Status = "failed"
		t.LastError = wire.Error
		m.log.Warn("transfer: falló", "id", wire.TransferID, "error", wire.Error)
		m.publishCompletion(ctx, t, "failed", nil)
		return nil
	}

	t.mu.Lock()
	if len(t.chunks) != t.ChunkCount {
		missing := t.ChunkCount - len(t.chunks)
		t.mu.Unlock()
		errMsg := fmt.Sprintf("chunks faltantes: %d", missing)
		t.Status = "failed"
		t.LastError = errMsg
		m.publishCompletion(ctx, t, "failed", nil)
		return fmt.Errorf("transfers: %s", errMsg)
	}
	var total []byte
	for i := 0; i < t.ChunkCount; i++ {
		c, ok := t.chunks[i]
		if !ok {
			t.mu.Unlock()
			return fmt.Errorf("transfers: chunk %d faltante", i)
		}
		total = append(total, c...)
	}
	t.mu.Unlock()

	// Verificar SHA-256.
	sum := sha256.Sum256(total)
	gotSum := hex.EncodeToString(sum[:])
	if t.SHA256 != "" && gotSum != t.SHA256 {
		t.Status = "failed"
		t.LastError = fmt.Sprintf("sha256 mismatch: got %s want %s", gotSum, t.SHA256)
		m.log.Warn("transfer: hash mismatch", "id", t.ID, "got", gotSum, "want", t.SHA256)
		m.publishCompletion(ctx, t, "failed", nil)
		return nil
	}

	outPath := filepath.Join(m.outputDir, sanitizeFilename(t.ID+"_"+t.Name))
	if err := os.WriteFile(outPath, total, 0o644); err != nil {
		t.Status = "failed"
		t.LastError = err.Error()
		m.publishCompletion(ctx, t, "failed", nil)
		return err
	}

	t.Status = "completed"
	t.CompletedAt = time.Now().UTC()
	m.log.Info("transfer: completado",
		"id", t.ID,
		"name", t.Name,
		"size", len(total),
		"sha256", gotSum,
		"output", outPath,
		"duration", t.CompletedAt.Sub(t.StartedAt).String(),
	)
	m.publishCompletion(ctx, t, "completed", []byte(fmt.Sprintf(
		"archivo descargado: %s (%d bytes, sha256=%s)\n",
		outPath, len(total), gotSum,
	)))
	return nil
}

// publishCompletion emite un TaskCompleted para que el operador vea el
// resultado como una tarea normal.
func (m *Manager) publishCompletion(ctx context.Context, t *Transfer, status string, output []byte) {
	if output == nil {
		output = []byte(fmt.Sprintf("transfer %s: %s (%s)\n", t.ID, status, t.LastError))
	}

	var taskUUID uuid.UUID
	if t.TaskID != "" {
		if id, err := uuid.Parse(t.TaskID); err == nil {
			taskUUID = id
		}
	}

	m.bus.Publish(ctx, events.Event{
		Topic: events.TopicTaskCompleted,
		Payload: map[string]any{
			"task_id":    taskUUID,
			"implant_id": t.ImplantID,
			"status":     status,
			"output":     output,
			"error":      t.LastError,
		},
	})
}

// sanitizeFilename elimina separadores de ruta y ".." para evitar
// path traversal si el cliente manda un nombre malicioso.
func sanitizeFilename(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '/' || c == '\\' || c == 0 {
			out = append(out, '_')
			continue
		}
		out = append(out, c)
	}
	// Reemplazar ".." por "__" para evitar traversal.
	s := string(out)
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '.' && s[i+1] == '.' {
			out[i] = '_'
			out[i+1] = '_'
		}
	}
	return string(out)
}

// List devuelve un snapshot de las transferencias activas.
func (m *Manager) List() []*Transfer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Transfer, 0, len(m.transfers))
	for _, t := range m.transfers {
		out = append(out, t)
	}
	return out
}
