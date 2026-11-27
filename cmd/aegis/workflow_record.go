package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector"
	"github.com/spf13/cobra"
)

func init() {
	// attached in workflowCmd via separate file build in same package; add command in workflow.go instead
}

func workflowRecordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "record",
		Short: "Control workflow recording in the connected browser (connector required)",
	}
	cmd.AddCommand(workflowRecordStartCmd(), workflowRecordStopCmd(), workflowRecordPauseCmd())
	return cmd
}

func workflowRecordStartCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start recording actions into a workflow",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("record.start", map[string]interface{}{"name": name}, 0)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(json.RawMessage(res.Data), "", "  ")
				fmt.Println(string(b))
				if !res.Success {
					if res.Err != nil {
						return fmt.Errorf("%s: %s", res.Err.Code, res.Err.Message)
					}
					return fmt.Errorf("%s", res.Error)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Workflow name")
	return cmd
}

func workflowRecordPauseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pause",
		Short: "Pause/resume active recording",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("record.pause", nil, 0)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(json.RawMessage(res.Data), "", "  ")
				fmt.Println(string(b))
				if !res.Success {
					if res.Err != nil {
						return fmt.Errorf("%s: %s", res.Err.Code, res.Err.Message)
					}
					return fmt.Errorf("%s", res.Error)
				}
				return nil
			})
		},
	}
	return cmd
}

func workflowRecordStopCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop recording and save workflow",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("record.stop", nil, 0)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(json.RawMessage(res.Data), "", "  ")
				if out != "" {
					_ = os.WriteFile(out, b, 0644)
				}
				fmt.Println(string(b))
				if !res.Success {
					if res.Err != nil {
						return fmt.Errorf("%s: %s", res.Err.Code, res.Err.Message)
					}
					return fmt.Errorf("%s", res.Error)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&out, "output", "", "Write stop/result JSON to file")
	return cmd
}
