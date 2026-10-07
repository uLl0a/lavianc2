package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// KeySize es el tamaño de clave AES-256 en bytes.
	KeySize = 32

	// NonceSize es el tamaño del nonce GCM en bytes.
	NonceSize = 12

	// TagSize es el tamaño del tag de autenticación GCM en bytes.
	TagSize = 16
)

// ErrInvalidBlob se devuelve cuando el blob cifrado es demasiado corto.
var ErrInvalidBlob = errors.New("crypto: blob cifrado inválido o demasiado corto")

// Encrypt cifra plaintext con AES-256-GCM usando la clave y el AAD dados.
//
// Formato de salida: nonce || ciphertext || tag
// donde nonce tiene NonceSize bytes y tag es el tag GCM estándar.
//
// El AAD (Additional Authenticated Data) es opcional; se autentica pero
// no se cifra. Útil para incluir metadatos como el ID del implante.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("crypto: la clave debe ser de 32 bytes (AES-256)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal añade el ciphertext + tag al slice nonce (prefijo).
	out := gcm.Seal(nonce, nonce, plaintext, aad)
	return out, nil
}

// Decrypt descifra un blob producido por Encrypt.
//
// Espera el formato: nonce || ciphertext || tag
func Decrypt(key, blob, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("crypto: la clave debe ser de 32 bytes (AES-256)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(blob) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrInvalidBlob
	}

	nonce := blob[:gcm.NonceSize()]
	ciphertext := blob[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// SecureZero sobreescribe un slice de bytes con ceros.
// Útil para limpiar claves de memoria tras su uso.
//
// Nota: en Go el compilador puede optimizar esto, pero es mejor que nada.
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
