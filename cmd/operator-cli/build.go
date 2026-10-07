package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	adminv1 "github.com/uLl0a/lavianc2/gen/admin/v1"
)

func buildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Compilar un nuevo implante",
		RunE: func(cmd *cobra.Command, args []string) error {
			listener, _ := cmd.Flags().GetString("listener")
			profile, _ := cmd.Flags().GetString("profile")
			targetOS, _ := cmd.Flags().GetString("os")
			arch, _ := cmd.Flags().GetString("arch")
			format, _ := cmd.Flags().GetString("format")
			sleep, _ := cmd.Flags().GetInt32("sleep")
			jitter, _ := cmd.Flags().GetInt32("jitter")
			compress, _ := cmd.Flags().GetBool("compress")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			resp, err := client.BuildImplant(ctx, &adminv1.BuildImplantRequest{
				ListenerUrl: listener,
				ProfileName: profile,
				TargetOs:    targetOS,
				TargetArch:  arch,
				Format:      format,
				SleepSecs:   sleep,
				JitterPerc:  jitter,
				Compress:    compress,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Build completado:\n")
			fmt.Printf("  ID:       %s\n", resp.BuildId)
			fmt.Printf("  Binario:  %s\n", resp.OutputPath)
			fmt.Printf("  Tamaño:   %d bytes\n", resp.SizeBytes)
			fmt.Printf("  Duración: %d ms\n", resp.DurationMs)
			return nil
		},
	}

	cmd.Flags().String("listener", "", "URL del listener C2 (requerido)")
	cmd.Flags().String("profile", "office365", "perfil maleable")
	cmd.Flags().String("os", "windows", "OS objetivo: windows, linux, darwin")
	cmd.Flags().String("arch", "amd64", "arquitectura: amd64, arm64, 386")
	cmd.Flags().String("format", "exe", "formato: exe, elf, macho")
	cmd.Flags().Int32("sleep", 60, "intervalo de sleep en segundos")
	cmd.Flags().Int32("jitter", 10, "porcentaje de jitter")
	cmd.Flags().Bool("compress", false, "comprimir con UPX")
	_ = cmd.MarkFlagRequired("listener")

	return cmd
}
