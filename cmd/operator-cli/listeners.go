package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	adminv1 "github.com/uLl0a/lavianc2/gen/admin/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func listenerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "listener",
		Short: "Gestión de listeners",
	}

	create := &cobra.Command{
		Use:   "create",
		Short: "Crear un listener",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			typ, _ := cmd.Flags().GetString("type")
			bindAddr, _ := cmd.Flags().GetString("bind")
			port, _ := cmd.Flags().GetInt32("port")
			domain, _ := cmd.Flags().GetString("domain")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			l, err := client.CreateListener(ctx, &adminv1.CreateListenerRequest{
				Name:     name,
				Type:     typ,
				BindAddr: bindAddr,
				Port:     port,
				Domain:   domain,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Listener creado: %s (ID: %s)\n", l.Name, l.Id)
			return nil
		},
	}
	create.Flags().String("name", "", "nombre del listener (requerido)")
	create.Flags().String("type", "https", "tipo: https, dns, mtls, http")
	create.Flags().String("bind", "0.0.0.0", "dirección de bind")
	create.Flags().Int32("port", 8443, "puerto")
	create.Flags().String("domain", "", "dominio asociado (DNS o mimetismo)")
	_ = create.MarkFlagRequired("name")

	list := &cobra.Command{
		Use:   "list",
		Short: "Listar listeners",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			resp, err := client.ListListeners(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}
			if len(resp.Listeners) == 0 {
				fmt.Println("No hay listeners registrados.")
				return nil
			}
			fmt.Printf("%-36s  %-14s  %-6s  %-20s  %-6s  %s\n",
				"ID", "NOMBRE", "TIPO", "BIND", "PORT", "ACTIVO")
			for _, l := range resp.Listeners {
				fmt.Printf("%-36s  %-14s  %-6s  %-20s  %-6d  %v\n",
					l.Id, l.Name, l.Type, l.BindAddr, l.Port, l.Active)
			}
			return nil
		},
	}

	cmd.AddCommand(create, list)
	return cmd
}
