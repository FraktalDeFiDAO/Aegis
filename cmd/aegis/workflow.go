package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector"
	"github.com/spf13/cobra"
)

func workflowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflow",
		Short: "Manage and run connector workflows (best-effort)",
	}
	cmd.AddCommand(workflowListCmd(), workflowRunCmd(), workflowExportCmd(), workflowImportCmd(), workflowDeleteCmd(), workflowRecordCmd())
	return cmd
}

func workflowDeleteCmd() *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a workflow from extension storage (connector required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return fmt.Errorf("--id is required")
			}
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("workflow.delete", map[string]string{"id": id}, 0)
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
	cmd.Flags().StringVar(&id, "id", "", "Workflow ID")
	return cmd
}

func withConnector(fn func(*connector.Connector) error) error {
	if !connectorMode {
		return fmt.Errorf("--connector is required for workflow operations that target the live browser")
	}
	_, conn, cleanup := getBrowserOrConnector(true)
	defer cleanup()
	if conn == nil {
		return fmt.Errorf("connector not available")
	}
	return fn(conn)
}

func workflowListCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List workflows stored in extension (connector required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("workflow.list", nil, 0)
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

func workflowRunCmd() *cobra.Command {
	var id string
	var file string
	var out string
	var captureScreenshots bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a workflow by id or from a JSON file (connector required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withConnector(func(conn *connector.Connector) error {
				params := map[string]interface{}{}
				if file != "" {
					b, err := os.ReadFile(file)
					if err != nil {
						return err
					}
					var wf interface{}
					if err := json.Unmarshal(b, &wf); err != nil {
						return fmt.Errorf("parse workflow file: %w", err)
					}
					params["workflow"] = wf
				} else if id != "" {
					params["id"] = id
				} else {
					return fmt.Errorf("--id or --file is required")
				}
				if captureScreenshots {
					params["captureScreenshots"] = true
				}
				res, err := conn.Send("workflow.run", params, 0)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(res, "", "  ")
				if out != "" {
					_ = os.WriteFile(out, b, 0644)
				}
				fmt.Println(string(b))
				if !res.Success {
					return fmt.Errorf("workflow run failed")
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "Workflow ID stored in extension")
	cmd.Flags().StringVar(&file, "file", "", "Workflow JSON file to run directly")
	cmd.Flags().StringVar(&out, "trace-out", "", "Write run result/trace JSON to file")
	cmd.Flags().BoolVar(&captureScreenshots, "capture-screenshots", false, "Capture page snapshots after key steps")
	return cmd
}

func workflowExportCmd() *cobra.Command {
	var id string
	var out string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a workflow from extension storage to JSON file (connector required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" || out == "" {
				return fmt.Errorf("--id and --output are required")
			}
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("workflow.get", map[string]string{"id": id}, 0)
				if err != nil {
					return err
				}
				if !res.Success {
					if res.Err != nil {
						return fmt.Errorf("%s: %s", res.Err.Code, res.Err.Message)
					}
					return fmt.Errorf("%s", res.Error)
				}
				var payload struct {
					Workflow json.RawMessage `json:"workflow"`
				}
				if err := json.Unmarshal(res.Data, &payload); err != nil {
					return err
				}
				data := payload.Workflow
				if len(data) == 0 {
					data = res.Data
				}
				var pretty interface{}
				_ = json.Unmarshal(data, &pretty)
				b, _ := json.MarshalIndent(pretty, "", "  ")
				if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil && !os.IsExist(err) && filepath.Dir(out) != "." {
					return err
				}
				return os.WriteFile(out, b, 0644)
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "Workflow ID")
	cmd.Flags().StringVar(&out, "output", "", "Output JSON file path")
	return cmd
}

func workflowImportCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import/save a workflow JSON file into extension storage (connector required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			b, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			var wf map[string]interface{}
			if err := json.Unmarshal(b, &wf); err != nil {
				return fmt.Errorf("parse workflow file: %w", err)
			}
			if wf["version"] == nil {
				wf["version"] = 1
			}
			if wf["id"] == nil || strings.TrimSpace(fmt.Sprint(wf["id"])) == "" {
				wf["id"] = "wf-" + fmt.Sprint(time.Now().Unix())
			}
			return withConnector(func(conn *connector.Connector) error {
				res, err := conn.Send("workflow.save", map[string]interface{}{"workflow": wf}, 0)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(b))
				if !res.Success {
					return fmt.Errorf("workflow import failed")
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Workflow JSON file path")
	return cmd
}
