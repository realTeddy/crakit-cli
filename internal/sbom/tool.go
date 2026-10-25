package sbom

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Tool selection values for --tool.
const (
	ToolAuto    = "auto"
	ToolBuiltin = "builtin"
	ToolSyft    = "syft"
	ToolCdxgen  = "cdxgen"
)

// LookPath is swappable for tests.
var LookPath = exec.LookPath

// DetectTool resolves the --tool value to a concrete tool name. With "auto"
// it prefers syft, then cdxgen, then the built-in generator.
func DetectTool(want string) (string, error) {
	switch want {
	case ToolBuiltin, "":
		return ToolBuiltin, nil
	case ToolSyft, ToolCdxgen:
		if _, err := LookPath(want); err != nil {
			return "", fmt.Errorf("%s not found on PATH", want)
		}
		return want, nil
	case ToolAuto:
		for _, t := range []string{ToolSyft, ToolCdxgen} {
			if _, err := LookPath(t); err == nil {
				return t, nil
			}
		}
		return ToolBuiltin, nil
	}
	return "", fmt.Errorf("unknown tool %q (want auto, builtin, syft or cdxgen)", want)
}

// RunExternal invokes syft or cdxgen on dir and returns the CycloneDX JSON.
// Nothing is sent anywhere; the tool runs locally.
func RunExternal(tool, dir string) ([]byte, error) {
	switch tool {
	case ToolSyft:
		cmd := exec.Command("syft", "scan", "dir:"+dir, "-o", "cyclonedx-json@1.6")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("syft: %w: %s", err, errb.String())
		}
		return out.Bytes(), nil
	case ToolCdxgen:
		tmp, err := os.MkdirTemp("", "crakit-cdxgen-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		outFile := filepath.Join(tmp, "bom.cdx.json")
		cmd := exec.Command("cdxgen", "-o", outFile, "--spec-version", "1.6", dir)
		var errb bytes.Buffer
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("cdxgen: %w: %s", err, errb.String())
		}
		return os.ReadFile(outFile)
	}
	return nil, fmt.Errorf("unsupported external tool %q", tool)
}
