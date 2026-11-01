// Command release cross-compiles the crakit CLI and packages one archive per
// platform plus a SHA256SUMS file. Standard library only.
//
//	go run ./scripts/release -version 0.1.0 -out dist
//
// Builds are reproducible: -trimpath, no VCS stamping, and archive entries carry
// a fixed timestamp (SOURCE_DATE_EPOCH when set, otherwise 1980-01-01).
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Target is one GOOS/GOARCH pair.
type Target struct{ OS, Arch string }

// Targets are the platforms published on every release.
var Targets = []Target{
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

var semver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// extraFiles are copied into every archive, relative to the cli directory.
var extraFiles = []string{"LICENSE", "NOTICE", "README.md"}

func main() {
	version := flag.String("version", "", "release version without the leading v, e.g. 0.1.0")
	out := flag.String("out", "dist", "output directory")
	flag.Parse()
	if err := run(*version, *out); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func run(version, out string) error {
	if !semver.MatchString(version) {
		return fmt.Errorf("version %q is not semver (no leading v)", version)
	}
	mtime := archiveTime()
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "crakit-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	var archives []string
	for _, t := range Targets {
		bin := filepath.Join(tmp, t.OS+"_"+t.Arch, BinaryName(t))
		if err := build(version, t, bin); err != nil {
			return fmt.Errorf("build %s/%s: %w", t.OS, t.Arch, err)
		}
		name := ArchiveName(version, t)
		files := append([]string{bin}, extraFiles...)
		dst := filepath.Join(out, name)
		if t.OS == "windows" {
			err = writeZip(dst, files, mtime)
		} else {
			err = writeTarGz(dst, files, mtime)
		}
		if err != nil {
			return fmt.Errorf("archive %s: %w", name, err)
		}
		archives = append(archives, dst)
		fmt.Println("built", name)
	}
	return writeSums(filepath.Join(out, "SHA256SUMS"), archives)
}

// BinaryName is the executable name inside the archive.
func BinaryName(t Target) string {
	if t.OS == "windows" {
		return "crakit.exe"
	}
	return "crakit"
}

// ArchiveName is the published file name for a target.
func ArchiveName(version string, t Target) string {
	ext := ".tar.gz"
	if t.OS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("crakit_%s_%s_%s%s", version, t.OS, t.Arch, ext)
}

func archiveTime() time.Time {
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
}

func build(version string, t Target, dst string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -X github.com/realTeddy/crakit/cli/internal/cmd.Version="+version,
		"-o", dst, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+t.OS, "GOARCH="+t.Arch)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func writeTarGz(dst string, files []string, mtime time.Time) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	gz.ModTime = mtime
	tw := tar.NewWriter(gz)
	for _, p := range files {
		data, mode, err := readFile(p)
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: filepath.Base(p), Mode: mode, Size: int64(len(data)), ModTime: mtime, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Close()
}

func writeZip(dst string, files []string, mtime time.Time) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, p := range files {
		data, mode, err := readFile(p)
		if err != nil {
			return err
		}
		hdr := &zip.FileHeader{Name: filepath.Base(p), Method: zip.Deflate, Modified: mtime}
		hdr.SetMode(os.FileMode(mode))
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return f.Close()
}

func readFile(p string) ([]byte, int64, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, 0, err
	}
	mode := int64(0o644)
	if b := filepath.Base(p); b == "crakit" || b == "crakit.exe" {
		mode = 0o755
	}
	return data, mode, nil
}

// SumLine formats one line of a sha256sum-compatible checksum file.
func SumLine(data []byte, name string) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]) + "  " + name
}

func writeSums(dst string, archives []string) error {
	sort.Strings(archives)
	var lines []string
	for _, a := range archives {
		f, err := os.Open(a)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		lines = append(lines, hex.EncodeToString(h.Sum(nil))+"  "+filepath.Base(a))
	}
	return os.WriteFile(dst, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}
