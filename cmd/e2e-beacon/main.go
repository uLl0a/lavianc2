package main

// e2e-beacon es un cliente de prueba del Multi-Beacon Manager.
// Uso:
//   e2e-beacon group  "nombre" "profile"
//   e2e-beacon list-groups
//   e2e-beacon register "nombre" "profile" [groupID]
//   e2e-beacon list
//   e2e-beacon profile "beaconID" "profile"
//   e2e-beacon stop "beaconID"
//   e2e-beacon start "beaconID"
//   e2e-beacon payload "beaconID" "bof|assembly|hvnc"

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

// connParams se sobreescriben con flags --server/--cert/--key/--ca
// (mismos nombres que operator-cli) para poder operar desde la red Docker.
var connParams struct {
	server string
	cert   string
	key    string
	ca     string
}

func connect() (adminv1.AdminServiceClient, *grpc.ClientConn, error) {
	server := connParams.server
	if server == "" {
		server = "localhost:9443"
	}
	cert := connParams.cert
	if cert == "" {
		cert = "certs/admin.crt"
	}
	key := connParams.key
	if key == "" {
		key = "certs/admin.key"
	}
	ca := connParams.ca
	if ca == "" {
		ca = "certs/ca.crt"
	}
	certPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, nil, err
	}
	caPEM, err := os.ReadFile(ca)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certPair},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})
	conn, err := grpc.NewClient(server, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, err
	}
	return adminv1.NewAdminServiceClient(conn), conn, nil
}

func main() {
	root := &cobra.Command{Use: "e2e-beacon", Short: "Cliente de prueba del Multi-Beacon Manager"}
	root.PersistentFlags().StringVar(&connParams.server, "server", "", "dirección del team server")
	root.PersistentFlags().StringVar(&connParams.cert, "cert", "", "certificado del operador")
	root.PersistentFlags().StringVar(&connParams.key, "key", "", "clave privada del operador")
	root.PersistentFlags().StringVar(&connParams.ca, "ca", "", "CA raíz")
	root.AddCommand(groupCmd(), listGroupsCmd(), registerCmd(), listCmd(),
		profileCmd(), stopCmd(), startCmd(), payloadCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func groupCmd() *cobra.Command {
	return &cobra.Command{
		Use: "group [nombre] [profile]",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, a []string) error {
			client, conn, err := connect()
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			g, err := client.CreateBeaconGroup(ctx, &adminv1.CreateBeaconGroupRequest{Name: a[0], Profile: a[1]})
			if err != nil {
				return err
			}
			fmt.Printf("grupo creado: %s (%s) profile=%s\n", g.Name, g.Id, g.Profile)
			return nil
		},
	}
}

func listGroupsCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list-groups",
		RunE: func(c *cobra.Command, a []string) error {
			client, conn, err := connect()
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			resp, err := client.ListBeaconGroups(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}
			for _, g := range resp.Groups {
				fmt.Printf("%s\t%s\t%s\n", g.Id[:8], g.Name, g.Profile)
			}
			return nil
		},
	}
}

func registerCmd() *cobra.Command {
	return &cobra.Command{
		Use: "register [nombre] [profile] [groupID]",
		Args: cobra.RangeArgs(2, 3),
		RunE: func(c *cobra.Command, a []string) error {
			client, conn, err := connect()
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			req := &adminv1.RegisterBeaconRequest{Name: a[0], Profile: a[1]}
			if len(a) == 3 {
				req.GroupId = a[2]
			}
			b, err := client.RegisterBeacon(ctx, req)
			if err != nil {
				return err
			}
			fmt.Printf("beacon registrado: %s (%s) profile=%s state=%s\n", b.Name, b.Id, b.Profile, b.State)
			return nil
		},
	}
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list",
		RunE: func(c *cobra.Command, a []string) error {
			client, conn, err := connect()
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			resp, err := client.ListBeacons(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}
			for _, b := range resp.Beacons {
				fmt.Printf("%s\t%s\t%s\tstate=%s\tracha=%d/%d\n",
					b.Id, b.Name, b.Profile, b.State, b.FailStreak, b.MaxFails)
			}
			return nil
		},
	}
}

func profileCmd() *cobra.Command {
	return &cobra.Command{
		Use: "profile [beaconID] [profile]",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, a []string) error {
			client, conn, err := connect()
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			b, err := client.SetBeaconProfile(ctx, &adminv1.SetBeaconProfileRequest{Id: a[0], Profile: a[1]})
			if err != nil {
				return err
			}
			fmt.Printf("beacon %s ahora profile=%s\n", b.Name, b.Profile)
			return nil
		},
	}
}

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use: "stop [beaconID]",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, a []string) error {
			client, conn, err := connect()
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := client.StopBeacon(ctx, &adminv1.BeaconControlRequest{Id: a[0]}); err != nil {
				return err
			}
			fmt.Println("beacon detenido (admin-stop)")
			return nil
		},
	}
}

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use: "start [beaconID]",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, a []string) error {
			client, conn, err := connect()
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := client.StartBeacon(ctx, &adminv1.BeaconControlRequest{Id: a[0]}); err != nil {
				return err
			}
			fmt.Println("beacon reactivado")
			return nil
		},
	}
}

func payloadCmd() *cobra.Command {
	var dataFile string
	cmd := &cobra.Command{
		Use: "payload [beaconID] [kind]",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, a []string) error {
			client, conn, err := connect()
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			var data []byte
			if dataFile != "" {
				data, err = os.ReadFile(dataFile)
				if err != nil {
					return fmt.Errorf("leer payload: %w", err)
				}
			} else {
				data = []byte("test-payload-rtc2")
			}

			_, err = client.SubmitDynamicPayload(ctx, &adminv1.SubmitDynamicPayloadRequest{
				BeaconId: a[0], Kind: a[1], Data: data,
			})
			if err != nil {
				fmt.Printf("RECHAZADO: %v\n", err)
				return nil // no es error de cliente; es la política actuando
			}
			fmt.Printf("payload %s (%d bytes) aceptado para beacon %s\n", a[1], len(data), a[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&dataFile, "data", "", "archivo con el payload binario")
	return cmd
}
