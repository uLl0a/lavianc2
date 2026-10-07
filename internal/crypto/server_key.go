package crypto

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type ServerKeyStore struct {
	mu  sync.RWMutex
	key *ecdh.PrivateKey

	privPath string
	pubPath  string
}

func LoadServerKeyStore(certDir string) (*ServerKeyStore, error) {
	if certDir == "" {
		return nil, errors.New("crypto: certDir requerido")
	}
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return nil, fmt.Errorf("crypto: crear cert dir: %w", err)
	}

	privPath := filepath.Join(certDir, "server_ecdh.key")
	pubPath := filepath.Join(certDir, "server_ecdh.pub")

	s := &ServerKeyStore{privPath: privPath, pubPath: pubPath}

	privBytes, err := os.ReadFile(privPath)
	if err == nil {
		priv, err := PrivateKeyFromBytes(privBytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parsear clave privada existente: %w", err)
		}
		s.key = priv
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("crypto: leer clave privada: %w", err)
	}

	// Slow path: generar y persistir.
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("crypto: generar par: %w", err)
	}
	if err := os.WriteFile(privPath, priv.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("crypto: escribir clave privada: %w", err)
	}
	if err := os.WriteFile(pubPath, pub.Bytes(), 0o644); err != nil {
		return nil, fmt.Errorf("crypto: escribir clave pública: %w", err)
	}
	s.key = priv
	return s, nil
}

func (s *ServerKeyStore) PrivateKey() *ecdh.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key
}

func (s *ServerKeyStore) PublicKey() *ecdh.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key.PublicKey()
}

func (s *ServerKeyStore) PublicKeyBase64() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return base64.StdEncoding.EncodeToString(s.key.PublicKey().Bytes())
}

func (s *ServerKeyStore) PrivateKeyPath() string {
	return s.privPath
}

func (s *ServerKeyStore) PublicKeyPath() string {
	return s.pubPath
}

func (s *ServerKeyStore) Rotate() error {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("crypto: generar par nuevo: %w", err)
	}
	if err := os.WriteFile(s.privPath, priv.Bytes(), 0o600); err != nil {
		return fmt.Errorf("crypto: escribir clave privada: %w", err)
	}
	if err := os.WriteFile(s.pubPath, pub.Bytes(), 0o644); err != nil {
		return fmt.Errorf("crypto: escribir clave pública: %w", err)
	}

	s.mu.Lock()
	old := s.key
	s.key = priv
	s.mu.Unlock()

	if old != nil {
		SecureZero(old.Bytes())
	}
	return nil
}
