package main

// e2e-builtin es un cliente de prueba que envía un comando built-in a un
// implante y espera su resultado. Existe para verificar FASE 1
// (comandos built-in core) sin necesidad de extender el CLI.
//
// Uso:
//   go run ./cmd/e2e-builtin --implant <id> --cmd ls --args /tmp
//   go run ./cmd/e2e-builtin --implant <id> --cmd download --args /etc/hostname

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
)

func main() {
	var implantID, cmd string
	var args []string
	var payloadFile string

	root := &cobra.Command{
		Use:   "e2e-builtin",
		Short: "Cliente de prueba para comandos built-in del implante",
		RunE: func(c *cobra.Command, a []string) error {
			return run(implantID, cmd, args, payloadFile)
		},
	}
	root.Flags().StringVar(&implantID, "implant", "", "UUID del implante (requerido)")
	root.Flags().StringVar(&cmd, "cmd", "", "comando built-in: ls,cd,pwd,cat,upload,download,ps,kill,execute,shell (requerido)")
	root.Flags().StringSliceVar(&args, "args", nil, "argumentos del comando")
	root.Flags().StringVar(&payloadFile, "payload", "", "archivo cuyo contenido va en el payload (upload)")
	_ = root.MarkFlagRequired("implant")
	_ = root.MarkFlagRequired("cmd")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(implantID, cmd string, args []string, payloadFile string) error {
	var payload []byte
	if payloadFile != "" {
		data, err := os.ReadFile(payloadFile)
		if err != nil {
			return fmt.Errorf("leer payload: %w", err)
		}
		payload = data
	}

	cert, err := tls.LoadX509KeyPair("certs/admin.crt", "certs/admin.key")
	if err != nil {
		return fmt.Errorf("cargar certificado: %w", err)
	}
	caPEM, err := os.ReadFile("certs/ca.crt")
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
	conn, err := grpc.NewClient("localhost:9443", grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("conectar: %w", err)
	}
	defer conn.Close()
	client := adminv1.NewAdminServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	task, err := client.SubmitTask(ctx, &adminv1.SubmitTaskRequest{
		ImplantId: implantID,
		Command:   cmd,
		Args:      args,
		Payload:   payload,
	})
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}
	fmt.Printf("tarea enviada: %s\n", task.Id)

	streamCtx, streamCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer streamCancel()
	stream, err := client.StreamTaskEvents(streamCtx, &adminv1.StreamTaskEventsRequest{ImplantId: implantID})
	if err != nil {
		return fmt.Errorf("stream: %w", err)
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if ev.TaskId != task.Id {
			continue // evento de otra tarea
		}
		fmt.Printf("[%s]\n%s", ev.Status, string(ev.Output))
		if ev.Error != "" {
			fmt.Printf("ERROR: %s\n", ev.Error)
		}
		if ev.Status == "completed" || ev.Status == "failed" {
			return nil
		}
	}
}