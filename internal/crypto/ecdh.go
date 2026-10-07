package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// GenerateKeyPair genera un par de claves X25519 para ECDH.
func GenerateKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey(), nil
}

// PublicKeyFromBytes reconstruye una clave pública X25519 desde su
// representación binaria (32 bytes).
func PublicKeyFromBytes(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != 32 {
		return nil, errors.New("crypto: clave pública X25519 debe tener 32 bytes")
	}
	return ecdh.X25519().NewPublicKey(b)
}

// PrivateKeyFromBytes reconstruye una clave privada X25519 desde su
// representación binaria (32 bytes).
func PrivateKeyFromBytes(b []byte) (*ecdh.PrivateKey, error) {
	if len(b) != 32 {
		return nil, errors.New("crypto: clave privada X25519 debe tener 32 bytes")
	}
	return ecdh.X25519().NewPrivateKey(b)
}

// DeriveSharedKey hace ECDH X25519 y luego HKDF-SHA256 para obtener
// una clave AES-256 de 32 bytes.
//
// El `info` sirve como contexto de derivación y permite obtener múltiples
// claves independientes del mismo secreto ECDH (por ejemplo, una clave
// para cada dirección del canal). El `salt` puede ser nil.
func DeriveSharedKey(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey, info []byte) ([]byte, error) {
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	return deriveKey(secret, nil, info)
}

// DeriveSharedKeyWithSalt es como DeriveSharedKey pero acepta salt explícito.
// Útil cuando el salt aporta entropía adicional (por ejemplo, un nonce de sesión).
func DeriveSharedKeyWithSalt(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey, salt, info []byte) ([]byte, error) {
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	return deriveKey(secret, salt, info)
}

// deriveKey aplica HKDF-SHA256 al secreto ECDH para obtener 32 bytes.
func deriveKey(secret, salt, info []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
