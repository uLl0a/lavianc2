package config

import (
	"os"
	"strconv"
)

// Config agrupa todos los parámetros de configuración del team server.
type Config struct {
	// DSN de PostgreSQL.
	// Ej: postgres://rtc2:rtc2@localhost:5432/rtc2?sslmode=disable
	DBDSN string

	// Dirección donde escucha el gRPC admin API.
	// Ej: ":9443"
	GRPCAddr string

	// Rutas a los certificados mTLS del server.
	TLSCertFile string
	TLSKeyFile  string
	CAFile      string

	// Dirección donde escucha el listener HTTPS del C2.
	// Ej: ":8443"
	HTTPSAddr string

	// Dirección donde escucha el listener DNS del C2.
	// Ej: ":5353"
	DNSAddr string

	// Dominio del listener DNS.
	// Ej: "c2.example.com"
	DNSDomain string

	// Nivel de log: "debug", "info", "warn", "error".
	LogLevel string
}

func Load() Config {
	return Config{
		DBDSN:       getenv("RTC2_DB_DSN", "postgres://rtc2:rtc2@localhost:5432/rtc2?sslmode=disable"),
		GRPCAddr:    getenv("RTC2_GRPC_ADDR", ":9443"),
		TLSCertFile: getenv("RTC2_TLS_CERT", "certs/server.crt"),
		TLSKeyFile:  getenv("RTC2_TLS_KEY", "certs/server.key"),
		CAFile:      getenv("RTC2_CA", "certs/ca.crt"),
		HTTPSAddr:   getenv("RTC2_HTTPS_ADDR", ":8443"),
		DNSAddr:     getenv("RTC2_DNS_ADDR", ":5353"),
		DNSDomain:   getenv("RTC2_DNS_DOMAIN", "c2.example.com"),
		LogLevel:    getenv("RTC2_LOG", "info"),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
