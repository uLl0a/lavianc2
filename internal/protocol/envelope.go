package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Magic identifica nuestro protocolo.
const Magic uint16 = 0xC2C2

// Version actual del protocolo.
const Version uint8 = 0x01

// MessageType mapea a constantes como en Sliver.
type MessageType uint32

const (
	MsgCheckin      MessageType = 1
	MsgTaskPull     MessageType = 2
	MsgTaskDispatch MessageType = 3
	MsgTaskResult   MessageType = 4
	MsgHeartbeat    MessageType = 5
	MsgTerminate    MessageType = 6
	MsgKeyExchange  MessageType = 7
	MsgKeyRotation  MessageType = 8
	MsgScreenshot   MessageType = 9
	MsgFileDownload MessageType = 10
	MsgFileUpload   MessageType = 11
	MsgProcessList  MessageType = 12
	MsgShellCommand MessageType = 13
	MsgPivot        MessageType = 14
	MsgBOF          MessageType = 15
	MsgTunnel       MessageType = 16 // frames de túnel persistente (hVNC/WS)
	MsgFileChunk    MessageType = 17
)

// Envelope es el wrapper genérico para toda comunicación C2.
// Formato wire: [magic:2B | version:1B | type:4B | length:4B | payload:N]
type Envelope struct {
	Magic   uint16
	Version uint8
	Type    MessageType
	Length  uint32
	Payload []byte
}

// HeaderSize es el tamaño del header binario sin payload.
const HeaderSize = 2 + 1 + 4 + 4 // 11 bytes

// Marshal serializa el envelope a formato wire.
func (e *Envelope) Marshal() ([]byte, error) {
	if e.Length != uint32(len(e.Payload)) {
		e.Length = uint32(len(e.Payload))
	}
	buf := make([]byte, HeaderSize+len(e.Payload))
	binary.BigEndian.PutUint16(buf[0:2], e.Magic)
	buf[2] = e.Version
	binary.BigEndian.PutUint32(buf[3:7], uint32(e.Type))
	binary.BigEndian.PutUint32(buf[7:11], e.Length)
	copy(buf[11:], e.Payload)
	return buf, nil
}

// UnmarshalEnvelope deserializa un envelope desde formato wire.
func UnmarshalEnvelope(data []byte) (*Envelope, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("protocol: envelope demasiado corto")
	}
	e := &Envelope{
		Magic:   binary.BigEndian.Uint16(data[0:2]),
		Version: data[2],
		Type:    MessageType(binary.BigEndian.Uint32(data[3:7])),
		Length:  binary.BigEndian.Uint32(data[7:11]),
	}
	if e.Magic != Magic {
		return nil, fmt.Errorf("protocol: magic inválido 0x%04X", e.Magic)
	}
	if e.Version != Version {
		return nil, fmt.Errorf("protocol: versión no soportada %d", e.Version)
	}
	if uint32(len(data)-HeaderSize) < e.Length {
		return nil, errors.New("protocol: payload incompleto")
	}
	e.Payload = make([]byte, e.Length)
	copy(e.Payload, data[HeaderSize:HeaderSize+e.Length])
	return e, nil
}

// NewEnvelope crea un envelope con payload.
func NewEnvelope(msgType MessageType, payload []byte) *Envelope {
	return &Envelope{
		Magic:   Magic,
		Version: Version,
		Type:    msgType,
		Length:  uint32(len(payload)),
		Payload: payload,
	}
}
