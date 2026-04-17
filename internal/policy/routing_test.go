package policy

import (
	"testing"

	"github.com/mirror-guard/auth-backend/internal/classifier"
)

func TestExtractFileExtension(t *testing.T) {
	if got := ExtractFileExtension("/ubuntu/pool/main/z/zstd_1.5.5.tar.xz"); got != ".xz" {
		t.Fatalf("ExtractFileExtension() = %q, want %q", got, ".xz")
	}
}

func TestClassifyRepoFamily(t *testing.T) {
	tests := []struct {
		path string
		want RepoFamily
	}{
		{path: "/ubuntu/dists/jammy/Release", want: LinuxDistro},
		{path: "/pypi/simple/requests/", want: LanguageEcosystem},
		{path: "/docker/library/nginx/manifests/latest", want: ContainerImage},
		{path: "/downloads/file.bin", want: Generic},
	}

	for _, tt := range tests {
		if got := ClassifyRepoFamily(tt.path); got != tt.want {
			t.Fatalf("ClassifyRepoFamily(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestClassifyDownloadBehavior(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		contentLength int64
		want          DownloadBehavior
	}{
		{name: "metadata root", path: "/", contentLength: 0, want: Metadata},
		{name: "metadata repodata", path: "/centos/8/repodata/repomd.xml", contentLength: 2048, want: Metadata},
		{name: "range resume via query", path: "/ubuntu/file.iso?range=bytes=1000-", contentLength: 10, want: RangeResume},
		{name: "large by extension", path: "/isos/debian.iso", contentLength: 2048, want: LargeFile},
		{name: "large by size", path: "/artifacts/archive.bin", contentLength: 200 * 1024 * 1024, want: LargeFile},
		{name: "small file", path: "/pypi/packages/pkg.whl", contentLength: 2 * 1024 * 1024, want: SmallFile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyDownloadBehavior(tt.path, tt.contentLength); got != tt.want {
				t.Fatalf("ClassifyDownloadBehavior(%q,%d) = %q, want %q", tt.path, tt.contentLength, got, tt.want)
			}
		})
	}
}

func TestRouteContextFieldsWorkTogether(t *testing.T) {
	path := "/ubuntu/releases/24.04/ubuntu-24.04-live-server-amd64.iso"
	ctx := RouteContext{
		Host:             "mirror.example.org",
		Path:             path,
		FileExtension:    ExtractFileExtension(path),
		RepoFamily:       ClassifyRepoFamily(path),
		DownloadBehavior: ClassifyDownloadBehavior(path, 1_900_000_000),
		ClientClass:      classifier.CLI,
	}

	if ctx.Host == "" || ctx.Path == "" {
		t.Fatal("expected host/path to be set")
	}
	if ctx.FileExtension != ".iso" {
		t.Fatalf("unexpected extension: %q", ctx.FileExtension)
	}
	if ctx.RepoFamily != LinuxDistro {
		t.Fatalf("unexpected repo family: %q", ctx.RepoFamily)
	}
	if ctx.DownloadBehavior != LargeFile {
		t.Fatalf("unexpected behavior: %q", ctx.DownloadBehavior)
	}
	if ctx.ClientClass != classifier.CLI {
		t.Fatalf("unexpected class: %q", ctx.ClientClass)
	}
}
