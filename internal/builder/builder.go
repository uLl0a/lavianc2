package builder

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

type Builder struct {
	RepoRoot string
	TempDir  string
	GoBinary string
}

func NewBuilder(repoRoot string) *Builder {
	return &Builder{
		RepoRoot: repoRoot,
		TempDir:  filepath.Join(repoRoot, ".build"),
		GoBinary: "go",
	}
}

func (b *Builder) Build(cfg *BuildConfig) (string, error) {
	if cfg.BuildID == "" {
		cfg.BuildID = uuid.New().String()
	}
	if cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = time.Now().UTC()
	}

	if err := cfg.Validate(); err != nil {
		return "", err
	}

	buildDir := filepath.Join(b.TempDir, cfg.BuildID)
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return "", fmt.Errorf("builder: crear dir temporal: %w", err)
	}
	defer os.RemoveAll(buildDir)

	src, err := RenderTemplate(cfg)
	if err != nil {
		return "", fmt.Errorf("builder: renderizar template: %w", err)
	}

	mainPath := filepath.Join(buildDir, "main.go")
	if err := os.WriteFile(mainPath, src, 0o644); err != nil {
		return "", fmt.Errorf("builder: escribir main.go: %w", err)
	}

	outputAbs, err := filepath.Abs(cfg.OutputPath)
	if err != nil {
		return "", fmt.Errorf("builder: resolver ruta de salida: %w", err)
	}
	args := b.buildArgs(cfg, outputAbs)

	cmd := exec.Command(b.GoBinary, args...)
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(),
		"GOOS="+string(cfg.TargetOS),
		"GOARCH="+string(cfg.TargetArch),
		"CGO_ENABLED=0",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("builder: go build falló: %w\n%s", err, stderr.String())
	}

	if cfg.Compress {
		if err := b.compress(outputAbs); err != nil {
			fmt.Fprintf(os.Stderr, "builder: advertencia: UPX falló: %v\n", err)
		}
	}

	return outputAbs, nil
}

// buildArgs construye los argumentos de go build.
func (b *Builder) buildArgs(cfg *BuildConfig, output string) []string {
	args := []string{"build", "-o", output}

	if !cfg.Debug {
		args = append(args, "-ldflags", "-s -w")
	}

	args = append(args, "-trimpath")
	args = append(args, ".")

	return args
}

// compress aplica UPX al binario si está disponible en el PATH.
func (b *Builder) compress(binary string) error {
	upxPath, err := exec.LookPath("upx")
	if err != nil {
		return fmt.Errorf("upx no encontrado en PATH")
	}
	cmd := exec.Command(upxPath, "--best", "--lzma", binary)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// BuildResult agrupa el resultado de una compilación.
type BuildResult struct {
	BuildID    string
	OutputPath string
	SizeBytes  int64
	Duration   time.Duration
}

func (b *Builder) BuildWithResult(cfg *BuildConfig) (*BuildResult, error) {
	start := time.Now()
	output, err := b.Build(cfg)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(output)
	if err != nil {
		return nil, err
	}
	return &BuildResult{
		BuildID:    cfg.BuildID,
		OutputPath: output,
		SizeBytes:  info.Size(),
		Duration:   time.Since(start),
	}, nil
}
