package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector"
	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
	"github.com/spf13/cobra"
)

type runtimeState struct {
	Addr      string    `json:"addr"`
	Port      int       `json:"port,omitempty"`
	Token     string    `json:"token"`
	TokenSet  bool      `json:"tokenSet,omitempty"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func connectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connector/bridge diagnostics and control",
	}
	cmd.AddCommand(connectServeCmd(), connectStatusCmd(), connectInfoCmd(), connectPolicyCmd(), connectAuditCmd(), connectAuditReportCmd(), connectSendCmd(), connectUploadCmd(), connectDownloadCmd())
	return cmd
}

func connectServeCmd() *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Keep the local browser extension bridge running until interrupted",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if port < 1 || port > 65535 {
				return fmt.Errorf("port must be between 1 and 65535")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			srv := bridge.NewServer(bridge.ServerConfig{Addr: "127.0.0.1", Port: port})
			addr, err := srv.StartNonBlocking(ctx)
			if err != nil {
				return err
			}
			defer srv.Stop()
			fmt.Fprintf(cmd.OutOrStdout(), "Aegis bridge listening on %s\nThe native host discovers authentication automatically. For manual extension setup, use the token in %s (keep it private). Press Ctrl+C to stop.\n", addr, defaultRuntimeStatePath())
			<-ctx.Done()
			return nil
		},
	}
	cmd.Flags().IntVar(&port, "port", 9876, "Local bridge port")
	return cmd
}

func connectInfoCmd() *cobra.Command {
	var bridge string
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show bridge /info diagnostics (localhost, no connector session required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			statePath := defaultRuntimeStatePath()
			if b, err := os.ReadFile(statePath); err == nil {
				var st runtimeState
				if json.Unmarshal(b, &st) == nil && bridge == "" && st.Addr != "" {
					bridge = "http://" + st.Addr
				}
			}
			if bridge == "" {
				bridge = "http://127.0.0.1:9876"
			}
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get(bridge + "/info")
			if err != nil {
				fmt.Printf("info: unreachable (%v)\n", err)
				return nil
			}
			defer resp.Body.Close()
			var info map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
				return fmt.Errorf("decode info: %w", err)
			}
			b, _ := json.MarshalIndent(info, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
	cmd.Flags().StringVar(&bridge, "bridge", "", "Bridge base URL (http://127.0.0.1:<port>)")
	return cmd
}

func connectPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Get/set local connector policy (best-effort, via extension/bridge)"}
	var mode string
	var out string
	cmd.Flags().StringVar(&mode, "mode", "", "Set policy mode: manual-approve, auto-with-prompts, unattended")
	cmd.Flags().StringVar(&out, "output", "", "Write JSON output to file")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !connectorMode {
			fmt.Println("status: requires --connector to query/update live extension policy")
			if mode != "" {
				fmt.Printf("requested_mode: %s\n", mode)
			}
			return nil
		}
		return withConnector(func(conn *connector.Connector) error {
			if mode != "" {
				res, err := conn.Send("policy.set", map[string]interface{}{"policy": map[string]interface{}{"mode": mode}}, 0)
				if err != nil {
					return err
				}
				if !res.Success {
					if res.Err != nil {
						return fmt.Errorf("%s: %s", res.Err.Code, res.Err.Message)
					}
					return fmt.Errorf("%s", res.Error)
				}
			}
			res, err := conn.Send("policy.get", nil, 0)
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
	}
	return cmd
}

func connectAuditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Fetch local connector policy/decision audit log (connector required)"}
	var out string
	var limit int
	cmd.Flags().StringVar(&out, "output", "", "Write JSON output to file")
	cmd.Flags().IntVar(&limit, "limit", 100, "Max audit entries to return")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !connectorMode {
			return fmt.Errorf("--connector is required")
		}
		return withConnector(func(conn *connector.Connector) error {
			res, err := conn.Send("audit.list", map[string]interface{}{"limit": limit}, 0)
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
	}
	return cmd
}

func connectAuditReportCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit-report", Short: "Fetch filtered audit report (connector required)"}
	var out string
	var limit int
	var typ string
	var outcome string
	var since int64
	var until int64
	var command string
	cmd.Flags().StringVar(&out, "output", "", "Write JSON output to file")
	cmd.Flags().IntVar(&limit, "limit", 500, "Max entries to return")
	cmd.Flags().StringVar(&typ, "type", "", "Filter by audit type (policy, task, etc)")
	cmd.Flags().StringVar(&outcome, "outcome", "", "Filter by outcome (allowed, denied, approval_required)")
	cmd.Flags().Int64Var(&since, "since", 0, "Filter by timestamp since (unix ms)")
	cmd.Flags().Int64Var(&until, "until", 0, "Filter by timestamp until (unix ms)")
	cmd.Flags().StringVar(&command, "command", "", "Filter by command name")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !connectorMode {
			return fmt.Errorf("--connector is required")
		}
		return withConnector(func(conn *connector.Connector) error {
			params := map[string]interface{}{"limit": limit}
			if typ != "" {
				params["type"] = typ
			}
			if outcome != "" {
				params["outcome"] = outcome
			}
			if since > 0 {
				params["since"] = since
			}
			if until > 0 {
				params["until"] = until
			}
			if command != "" {
				params["command"] = command
			}
			res, err := conn.Send("audit.report", params, 0)
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
	}
	return cmd
}

func connectSendCmd() *cobra.Command {
	var command string
	var paramsJSON string
	var paramsFile string
	var timeout time.Duration
	var out string
	cmd := &cobra.Command{
		Use:   "send",
		Short: "Send a raw connector command for diagnostics (connector required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if command == "" {
				return fmt.Errorf("--command is required")
			}
			var params map[string]interface{}
			if paramsFile != "" {
				b, err := os.ReadFile(paramsFile)
				if err != nil {
					return err
				}
				paramsJSON = string(b)
			}
			if paramsJSON != "" {
				if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
					return fmt.Errorf("parse --params: %w", err)
				}
			}
			if !connectorMode {
				return fmt.Errorf("--connector is required")
			}
			return withConnector(func(conn *connector.Connector) error {
				if timeout <= 0 {
					return fmt.Errorf("timeout must be positive")
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
				defer cancel()
				res, err := conn.SendContext(ctx, command, params, 0)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(res, "", "  ")
				if out != "" {
					if err := os.WriteFile(out, b, 0600); err != nil {
						return err
					}
				} else {
					fmt.Println(string(b))
				}
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
	cmd.Flags().StringVar(&command, "command", "", "Raw protocol command name (e.g. listTabs, policy.get)")
	cmd.Flags().StringVar(&paramsJSON, "params", "", "JSON object params")
	cmd.Flags().StringVar(&paramsFile, "params-file", "", "Read JSON params from a private file instead of process arguments")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Browser command timeout")
	cmd.MarkFlagsMutuallyExclusive("params", "params-file")
	cmd.Flags().StringVar(&out, "output", "", "Write JSON output to file")
	return cmd
}

func connectStatusCmd() *cobra.Command {
	var bridge string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show bridge runtime state and health (localhost)",
		RunE: func(cmd *cobra.Command, args []string) error {
			statePath := defaultRuntimeStatePath()
			if b, err := os.ReadFile(statePath); err == nil {
				var st runtimeState
				if json.Unmarshal(b, &st) == nil {
					fmt.Printf("runtime_state_path: %s\n", statePath)
					fmt.Printf("addr: %s\n", st.Addr)
					fmt.Printf("protocol_version: %d\n", st.Version)
					fmt.Printf("updated_at: %s\n", st.UpdatedAt.Format(time.RFC3339))
					if bridge == "" && st.Addr != "" {
						bridge = "http://" + st.Addr
					}
				}
			} else {
				fmt.Printf("runtime_state_path: %s (not found)\n", statePath)
			}
			if bridge == "" {
				bridge = "http://127.0.0.1:9876"
			}
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get(bridge + "/health")
			if err != nil {
				fmt.Printf("health: unreachable (%v)\n", err)
				fmt.Println("status: bridge not running or not reachable")
				return nil
			}
			defer resp.Body.Close()
			var health map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
				return fmt.Errorf("decode health: %w", err)
			}
			fmt.Printf("health: ok (status=%v extensionConnected=%v pendingCommands=%v)\n", health["status"], health["extensionConnected"], health["pendingCommands"])
			return nil
		},
	}
	cmd.Flags().StringVar(&bridge, "bridge", "", "Bridge base URL (http://127.0.0.1:<port>), defaults to runtime state or 127.0.0.1:9876")
	return cmd
}

func defaultRuntimeStatePath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "aegis", "connector", "runtime.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "aegis", "connector", "runtime.json")
}

// Prefer the bridge already started by the browser's native host. Runtime state
// is advisory and must never redirect a local connector to a remote machine.
func discoveredBridge() (string, string) {
	const fallback = "ws://127.0.0.1:9876/ws?client=aegis"
	path := defaultRuntimeStatePath()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fallback, ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback, ""
	}
	var state runtimeState
	if json.Unmarshal(b, &state) != nil {
		return fallback, ""
	}
	host, port, err := net.SplitHostPort(state.Addr)
	if err != nil {
		return fallback, ""
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || n < 1 || n > 65535 {
		return fallback, ""
	}
	return "ws://" + net.JoinHostPort(host, port) + "/ws?client=aegis", state.Token
}

func discoveredBridgeURL() string {
	url, _ := discoveredBridge()
	return url
}

func discoveredBridgeToken(wsURL string) string {
	discovered, token := discoveredBridge()
	requestedKey := controllerURLKey(wsURL)
	if requestedKey == "" || requestedKey != controllerURLKey(discovered) {
		return ""
	}
	return token
}

func controllerURLKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ws" || u.Host == "" || u.Path != "/ws" || u.User != nil || u.Fragment != "" {
		return ""
	}
	query := u.Query()
	client := query.Get("client")
	if client == "" {
		client = "aegis"
	}
	query.Del("client")
	if client != "aegis" || len(query) != 0 {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}
