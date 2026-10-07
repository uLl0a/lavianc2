package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	adminv1 "github.com/uLl0a/lavianc2/gen/admin/v1"
)

func taskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "task",
		Short: "Gestión de tareas",
	}

	submit := &cobra.Command{
		Use:   "submit [implant-id] [comando] [args...]",
		Short: "Enviar una tarea a un implante",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			implantID := args[0]
			command := args[1]
			taskArgs := args[2:]

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			t, err := client.SubmitTask(ctx, &adminv1.SubmitTaskRequest{
				ImplantId: implantID,
				Command:   command,
				Args:      taskArgs,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Tarea enviada:\n")
			fmt.Printf("  ID:       %s\n", t.Id)
			fmt.Printf("  Implant:  %s\n", t.ImplantId)
			fmt.Printf("  Comando:  %s\n", t.Command)
			fmt.Printf("  Args:     %v\n", t.Args)
			fmt.Printf("  Estado:   %s\n", t.Status)
			return nil
		},
	}

	stream := &cobra.Command{
		Use:   "stream [implant-id]",
		Short: "Streamear eventos de tareas de un implante",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			implantID := args[0]

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s, err := client.StreamTaskEvents(ctx, &adminv1.StreamTaskEventsRequest{
				ImplantId: implantID,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Escuchando eventos para implante %s...\n", implantID)
			for {
				ev, err := s.Recv()
				if err != nil {
					return err
				}
				fmt.Printf("[%s] task=%s\n",
					ev.At.AsTime().Format("15:04:05"), ev.TaskId)
				fmt.Printf("  Estado: %s\n", ev.Status)
				if len(ev.Output) > 0 {
					fmt.Printf("  Output: %s\n", string(ev.Output))
				}
				if ev.Error != "" {
					fmt.Printf("  Error:  %s\n", ev.Error)
				}
				if ev.Status == "completed" || ev.Status == "failed" {
					fmt.Println("---")
				}
			}
		},
	}

	cmd.AddCommand(submit, stream)
	return cmd
}
