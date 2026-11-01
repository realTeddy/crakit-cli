package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArchiveNames(t *testing.T) {
	if got := ArchiveName("0.1.0", Target{"linux", "amd64"}); got != "crakit_0.1.0_linux_amd64.tar.gz" {
		t.Fatalf("linux name %q", got)
	}
	if got := ArchiveName("0.1.0", Target{"windows", "arm64"}); got != "crakit_0.1.0_windows_arm64.zip" {
		t.Fatalf("windows name %q", got)
	}
	if BinaryName(Target{"windows", "amd64"}) != "crakit.exe" || BinaryName(Target{"darwin", "arm64"}) != "crakit" {
		t.Fatal("binary names")
	}
}

func TestRejectsBadVersion(t *testing.T) {
	for _, v := range []string{"", "v0.1.0", "0.1", "latest"} {
		if err := run(v, t.TempDir()); err == nil {
			t.Fatalf("version %q accepted", v)
		}
	}
}

func TestSumLineMatchesSha256sum(t *testing.T) {
	// printf 'abc' | sha256sum
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  f"
	if got := SumLine([]byte("abc"), "f"); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestTarGzIsReproducible(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "crakit")
	if err := os.WriteFile(src, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	mt := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	a, b := filepath.Join(dir, "a.tar.gz"), filepath.Join(dir, "b.tar.gz")
	if err := writeTarGz(a, []string{src}, mt); err != nil {
		t.Fatal(err)
	}
	if err := writeTarGz(b, []string{src}, mt); err != nil {
		t.Fatal(err)
	}
	da, _ := os.ReadFile(a)
	db, _ := os.ReadFile(b)
	if string(da) != string(db) {
		t.Fatal("archives differ")
	}
	f, _ := os.Open(a)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := tar.NewReader(gz).Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "crakit" || hdr.Mode != 0o755 || !hdr.ModTime.Equal(mt) {
		t.Fatalf("header %+v", hdr)
	}
}
