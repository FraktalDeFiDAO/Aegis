package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector"
	"github.com/spf13/cobra"
)

func browserData(ctx context.Context, conn *connector.Connector, command string, params any, tabID int) (json.RawMessage, error) {
	res, err := conn.SendContext(ctx, command, params, tabID)
	if err != nil {
		return nil, err
	}
	if !res.Success {
		if res.Err != nil {
			return nil, fmt.Errorf("%s: %s", res.Err.Code, res.Err.Message)
		}
		return nil, fmt.Errorf("browser command rejected: %s", res.Error)
	}
	return res.Data, nil
}

type selectedFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

func connectUploadCmd() *cobra.Command {
	var tabID, frameID int
	var selector, transport string
	var files []string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "upload", Short: "Select local files in a browser file input; does not verify server acceptance", Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !connectorMode || tabID <= 0 || frameID < 0 || selector == "" || len(files) == 0 || timeout <= 0 {
			return fmt.Errorf("--connector, --tab-id, --selector and --file are required; frame-id must be nonnegative")
		}
		if transport != "auto" && transport != "native" && transport != "stream" {
			return fmt.Errorf("transport must be auto, native, or stream")
		}
		stream := transport == "stream" || (transport == "auto" && frameID != 0)
		if stream && len(files) != 1 {
			return fmt.Errorf("stream transport currently accepts one file; use native transport for multiple files")
		}
		paths := make([]string, len(files))
		expected := make([]selectedFile, len(files))
		for i, path := range files {
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			info, err := os.Stat(abs)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("not a regular file: %s", path)
			}
			if stream && info.Size() > 256*1024*1024 {
				return fmt.Errorf("stream upload limit is 256 MiB; use native transport for larger files")
			}
			paths[i] = abs
			expected[i] = selectedFile{Name: filepath.Base(abs), Size: info.Size()}
		}
		return withConnector(func(conn *connector.Connector) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			var data json.RawMessage
			var err error
			if stream {
				data, err = streamUpload(ctx, conn, tabID, frameID, selector, paths[0], expected[0].Size)
			} else {
				data, err = browserData(ctx, conn, "upload.file", map[string]any{"tabId": tabID, "frameId": frameID, "selector": selector, "paths": paths}, tabID)
				if err == nil {
					var result struct {
						Selected bool           `json:"selected"`
						Files    []selectedFile `json:"files"`
					}
					if json.Unmarshal(data, &result) != nil || !result.Selected || len(result.Files) != len(expected) {
						return fmt.Errorf("file selection was not verified")
					}
					for i, got := range result.Files {
						if got.Name != expected[i].Name || got.Size != expected[i].Size {
							return fmt.Errorf("selected file metadata does not match local file %s", expected[i].Name)
						}
					}
				}
			}
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"success": true, "data": json.RawMessage(data)})
		})
	}
	cmd.Flags().IntVar(&tabID, "tab-id", 0, "Explicit target browser tab ID")
	cmd.Flags().IntVar(&frameID, "frame-id", 0, "Explicit target frame ID (0 = top frame)")
	cmd.Flags().StringVar(&selector, "selector", "", "File input CSS selector; >>> enters open shadow roots")
	cmd.Flags().StringArrayVar(&files, "file", nil, "Local filename; repeat for multiple files using native transport")
	cmd.Flags().StringVar(&transport, "transport", "auto", "auto (native top frame, stream child frame), native, or stream")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Total transfer timeout")
	return cmd
}

func streamUpload(ctx context.Context, conn *connector.Connector, tabID, frameID int, selector, path string, size int64) (json.RawMessage, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	params := map[string]any{"tabId": tabID, "frameId": frameID, "selector": selector, "filename": filepath.Base(path), "size": size, "mimeType": mime.TypeByExtension(filepath.Ext(path))}
	data, err := browserData(ctx, conn, "upload.begin", params, tabID)
	if err != nil {
		return nil, err
	}
	var begin struct {
		TransferID string `json:"transferId"`
	}
	if json.Unmarshal(data, &begin) != nil || begin.TransferID == "" {
		return nil, fmt.Errorf("invalid upload.begin result")
	}
	finished := false
	defer func() {
		if !finished {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = browserData(cleanup, conn, "upload.cancel", map[string]any{"transferId": begin.TransferID, "frameId": frameID}, tabID)
		}
	}()
	hash := sha256.New()
	buffer := make([]byte, 256*1024)
	var offset int64
	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			payload := map[string]any{"frameId": frameID, "transferId": begin.TransferID, "offset": offset, "content": base64.StdEncoding.EncodeToString(buffer[:n])}
			ack, sendErr := browserData(ctx, conn, "upload.chunk", payload, tabID)
			if sendErr != nil {
				return nil, sendErr
			}
			offset += int64(n)
			var chunk struct {
				NextOffset int64 `json:"nextOffset"`
			}
			if json.Unmarshal(ack, &chunk) != nil || chunk.NextOffset != offset {
				return nil, fmt.Errorf("upload chunk acknowledgment mismatch")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	if offset != size {
		return nil, fmt.Errorf("local file changed size during upload")
	}
	sha := hex.EncodeToString(hash.Sum(nil))
	data, err = browserData(ctx, conn, "upload.finish", map[string]any{"frameId": frameID, "transferId": begin.TransferID, "sha256": sha}, tabID)
	if err != nil {
		return nil, err
	}
	var result struct {
		Selected bool   `json:"selected"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
	}
	if json.Unmarshal(data, &result) != nil || !result.Selected || result.Size != size || result.SHA256 != sha {
		return nil, fmt.Errorf("upload completion integrity check failed")
	}
	finished = true
	return data, nil
}

func connectDownloadCmd() *cobra.Command {
	var tabID, id int
	var url, output string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "download", Short: "Start or retrieve a completed browser download to a local file", Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !connectorMode || tabID <= 0 || output == "" || (url == "" && id < 0) || (url != "" && id >= 0) || timeout <= 0 {
			return fmt.Errorf("--connector, --tab-id, --output, and exactly one of --id or --url are required")
		}
		if _, err := os.Lstat(output); err == nil {
			return fmt.Errorf("destination already exists: %s", output)
		} else if !os.IsNotExist(err) {
			return err
		}
		return withConnector(func(conn *connector.Connector) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			if url != "" {
				data, err := browserData(ctx, conn, "download.start", map[string]any{"url": url, "tabId": tabID}, tabID)
				if err != nil {
					return err
				}
				var started struct {
					ID *int `json:"id"`
				}
				if json.Unmarshal(data, &started) != nil || started.ID == nil {
					return fmt.Errorf("invalid download.start result")
				}
				id = *started.ID
			}
			// Poll bounded short requests rather than leaving a single command outstanding for minutes.
			var item struct {
				ID         int    `json:"id"`
				Filename   string `json:"filename"`
				State      string `json:"state"`
				Error      string `json:"error"`
				TotalBytes int64  `json:"totalBytes"`
			}
			for {
				data, err := browserData(ctx, conn, "download.list", map[string]any{"query": map[string]any{"id": id}}, tabID)
				if err != nil {
					return err
				}
				var listing struct {
					Downloads []json.RawMessage `json:"downloads"`
				}
				if json.Unmarshal(data, &listing) != nil || len(listing.Downloads) != 1 {
					return fmt.Errorf("download ID not found or ambiguous: %d", id)
				}
				if err := json.Unmarshal(listing.Downloads[0], &item); err != nil {
					return err
				}
				if item.ID != id {
					return fmt.Errorf("download ID mismatch")
				}
				if item.State == "interrupted" {
					return fmt.Errorf("download %d was interrupted: %s", id, item.Error)
				}
				if item.State == "complete" {
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(500 * time.Millisecond):
				}
			}
			if !filepath.IsAbs(item.Filename) {
				return fmt.Errorf("browser did not return an absolute completed filename")
			}
			sha, size, err := copyDownload(item.Filename, output, item.TotalBytes)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"success": true, "id": id, "output": output, "bytes": size, "sha256": sha})
		})
	}
	cmd.Flags().IntVar(&tabID, "tab-id", 0, "Explicit browser tab ID for local policy evaluation")
	cmd.Flags().IntVar(&id, "id", -1, "Existing browser download ID")
	cmd.Flags().StringVar(&url, "url", "", "Start a download from this URL")
	cmd.Flags().StringVar(&output, "output", "", "New local destination file; existing files are preserved")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Total download timeout")
	return cmd
}

func copyDownload(source, destination string, expected int64) (string, int64, error) {
	file, err := os.Open(source)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("download is not a regular file")
	}
	if expected >= 0 && info.Size() != expected {
		return "", 0, fmt.Errorf("completed download size does not match browser metadata")
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".aegis-download-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(temp, hash), file)
	if err != nil {
		return "", size, err
	}
	after, err := file.Stat()
	if err != nil {
		return "", size, err
	}
	if size != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", size, fmt.Errorf("download changed while reading")
	}
	if err := temp.Sync(); err != nil {
		return "", size, err
	}
	if err := temp.Close(); err != nil {
		return "", size, err
	}
	// Hard-link atomically into place without overwriting an existing file/symlink.
	if err := os.Link(temp.Name(), destination); err != nil {
		return "", size, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
