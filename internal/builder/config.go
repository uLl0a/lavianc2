package builder

import (
	"fmt"
	"runtime"
	"time"
)

type TargetOS string

const (
	TargetWindows TargetOS = "windows"
	TargetLinux   TargetOS = "linux"
	TargetDarwin  TargetOS = "darwin"
)

type TargetArch string

const (
	ArchAMD64 TargetArch = "amd64"
	ArchARM64 TargetArch = "arm64"
	Arch386   TargetArch = "386"
)

type OutputFormat string

const (
	FormatEXE       OutputFormat = "exe"
	FormatDLL       OutputFormat = "dll"
	FormatShellcode OutputFormat = "shellcode"
	FormatELF       OutputFormat = "elf"
	FormatMachO     OutputFormat = "macho"
)

// BuildConfig agrupa todos los parámetros de una compilación.
type BuildConfig struct {
	// Identificación
	BuildID   string // UUID único de esta compilación
	CreatedAt time.Time

	// Objetivo
	TargetOS   TargetOS
	TargetArch TargetArch
	Format     OutputFormat

	// Infraestructura C2
	ListenerURL  string // ej: "https://c2.example.com/api/v1/envelope"
	ProfileName  string // ej: "office365"
	ServerPubKey string // base64 de la clave pública X25519 del server

	CACertPEMBase64 string

	// Comportamiento
	SleepSecs  int // intervalo base de sleep
	JitterPerc int // porcentaje de jitter

	// Opciones de compilación
	Obfuscate  bool // aplicar garble (ofuscación de símbolos)
	Compress   bool // aplicar UPX
	Debug      bool // incluir símbolos de debug
	OutputPath string
}

// Validate comprueba que la configuración es coherente.
func (c *BuildConfig) Validate() error {
	if c.ListenerURL == "" {
		return fmt.Errorf("builder: ListenerURL requerido")
	}
	if c.ProfileName == "" {
		return fmt.Errorf("builder: ProfileName requerido")
	}
	if c.ServerPubKey == "" {
		return fmt.Errorf("builder: ServerPubKey requerido")
	}

	if c.CACertPEMBase64 == "" {
		return fmt.Errorf("builder: CACertPEMBase64 requerido")
	}
	if c.TargetOS == "" {
		c.TargetOS = TargetOS(runtime.GOOS)
	}
	if c.TargetArch == "" {
		c.TargetArch = TargetArch(runtime.GOARCH)
	}
	if c.SleepSecs <= 0 {
		c.SleepSecs = 60
	}
	if c.JitterPerc < 0 || c.JitterPerc > 100 {
		c.JitterPerc = 10
	}
	if c.OutputPath == "" {
		shortID := c.BuildID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		if shortID == "" {
			shortID = "build"
		}
		c.OutputPath = fmt.Sprintf("implant_%s_%s_%s", c.TargetOS, c.TargetArch, shortID)
		if c.TargetOS == TargetWindows {
			c.OutputPath += ".exe"
		}
	}
	return nil
}

// DefaultConfig devuelve una configuración sensata para pruebas.
func DefaultConfig(listenerURL, profileName, serverPubKey string) *BuildConfig {
	return &BuildConfig{
		TargetOS:     TargetWindows,
		TargetArch:   ArchAMD64,
		Format:       FormatEXE,
		ListenerURL:  listenerURL,
		ProfileName:  profileName,
		ServerPubKey: serverPubKey,
		SleepSecs:    60,
		JitterPerc:   10,
		Obfuscate:    false,
		Compress:     false,
		Debug:        false,
	}
}
