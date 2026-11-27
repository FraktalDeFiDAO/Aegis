package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector"
	"github.com/spf13/cobra"
)

func scheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage connector schedules (best-effort, connector required)",
	}
	cmd.AddCommand(scheduleListCmd(), scheduleCreateCmd(), scheduleDeleteCmd(), scheduleRunsCmd())
	return cmd
}

func scheduleListCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List schedules stored in extension",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("schedule.list", nil, 0)
				if err != nil {
					return err
				}
				if !res.Success {
					if res.Err != nil {
						return fmt.Errorf("%s: %s", res.Err.Code, res.Err.Message)
					}
					return fmt.Errorf("%s", res.Error)
				}
				b, _ := json.MarshalIndent(json.RawMessage(res.Data), "", "  ")
				if out != "" {
					return os.WriteFile(out, b, 0644)
				}
				fmt.Println(string(b))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&out, "output", "", "Write JSON output to file")
	return cmd
}

func scheduleCreateCmd() *cobra.Command {
	var name, workflowID, command string
	var interval int
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a schedule for a workflow or command",
		RunE: func(cmd *cobra.Command, args []string) error {
			if workflowID == "" && command == "" {
				return fmt.Errorf("--workflow-id or --command is required")
			}
			params := map[string]interface{}{
				"name":            name,
				"workflowId":      workflowID,
				"command":         command,
				"intervalMinutes": interval,
				"enabled":         true,
			}
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("schedule.create", params, 0)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(json.RawMessage(res.Data), "", "  ")
				fmt.Println(string(b))
				if !res.Success {
					return fmt.Errorf("schedule create failed")
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Schedule name")
	cmd.Flags().StringVar(&workflowID, "workflow-id", "", "Workflow ID to run")
	cmd.Flags().StringVar(&command, "command", "", "Command name to run (simple schedules)")
	cmd.Flags().IntVar(&interval, "interval-minutes", 60, "Interval in minutes (min 1)")
	return cmd
}

func scheduleDeleteCmd() *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a schedule by id",
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return fmt.Errorf("--id is required")
			}
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("schedule.delete", map[string]string{"id": id}, 0)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(json.RawMessage(res.Data), "", "  ")
				fmt.Println(string(b))
				if !res.Success {
					return fmt.Errorf("schedule delete failed")
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "Schedule ID")
	return cmd
}

func scheduleRunsCmd() *cobra.Command {
	var out string
	var limit int
	cmd := &cobra.Command{
		Use:   "runs",
		Short: "List recorded schedule/workflow runs (best-effort)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("schedule.runs", map[string]interface{}{"limit": limit}, 0)
				if err != nil {
					return err
				}
				if !res.Success {
					if res.Err != nil {
						return fmt.Errorf("%s: %s", res.Err.Code, res.Err.Message)
					}
					return fmt.Errorf("%s", res.Error)
				}
				b, _ := json.MarshalIndent(json.RawMessage(res.Data), "", "  ")
				if out != "" {
					return os.WriteFile(out, b, 0644)
				}
				fmt.Println(string(b))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&out, "output", "", "Write JSON output to file")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max runs to return")
	return cmd
}
