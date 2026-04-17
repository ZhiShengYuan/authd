package policy

import (
	"path/filepath"
	"strings"

	"github.com/mirror-guard/auth-backend/internal/classifier"
)

type DownloadBehavior string

const (
	Metadata    DownloadBehavior = "metadata"
	SmallFile   DownloadBehavior = "small_file"
	LargeFile   DownloadBehavior = "large_file"
	RangeResume DownloadBehavior = "range_resume"
)

type RepoFamily string

const (
	LinuxDistro       RepoFamily = "linux_distro"
	LanguageEcosystem RepoFamily = "language_ecosystem"
	ContainerImage    RepoFamily = "container_image"
	Generic           RepoFamily = "generic"
)

type RouteContext struct {
	Host             string
	Path             string
	FileExtension    string
	RepoFamily       RepoFamily
	DownloadBehavior DownloadBehavior
	ClientClass      classifier.ClientClass
}

var metadataPathIndicators = []string{
	"/repodata/",
	"/inrelease",
	"/metadata/",
	"/index",
}

var largeFileExtensions = []string{
	".iso",
	".tar.xz",
}

var linuxRepoIndicators = []string{
	"/ubuntu/",
	"/debian/",
	"/centos/",
	"/fedora/",
	"/archlinux/",
}

var languageRepoIndicators = []string{
	"/pypi/",
	"/npm/",
	"/crates.io/",
	"/rubygems/",
	"/nuget/",
}

var containerRepoIndicators = []string{
	"/docker/",
	"/container/",
}

func ClassifyDownloadBehavior(path string, contentLength int64) DownloadBehavior {
	cleanPath := stripQuery(path)
	pathLower := strings.ToLower(cleanPath)

	if strings.Contains(strings.ToLower(path), "range=") || strings.Contains(strings.ToLower(path), "resume=") {
		return RangeResume
	}

	if isMetadataPath(pathLower) {
		return Metadata
	}

	for _, ext := range largeFileExtensions {
		if strings.HasSuffix(pathLower, ext) {
			return LargeFile
		}
	}

	if contentLength >= 100*1024*1024 {
		return LargeFile
	}

	return SmallFile
}

func ClassifyRepoFamily(path string) RepoFamily {
	pathLower := strings.ToLower(path)

	if containsAnyPathIndicator(pathLower, linuxRepoIndicators) {
		return LinuxDistro
	}

	if containsAnyPathIndicator(pathLower, languageRepoIndicators) {
		return LanguageEcosystem
	}

	if containsAnyPathIndicator(pathLower, containerRepoIndicators) {
		return ContainerImage
	}

	return Generic
}

func ExtractFileExtension(path string) string {
	return strings.ToLower(filepath.Ext(path))
}

func isMetadataPath(path string) bool {
	if path == "" || path == "/" {
		return true
	}

	if strings.Contains(path, "/repodata/") {
		return true
	}
	if strings.HasSuffix(path, "/packages") || strings.HasSuffix(path, "/packages.gz") || strings.HasSuffix(path, "/packages.xz") {
		return true
	}
	if strings.HasSuffix(path, "/release") || strings.HasSuffix(path, "/inrelease") {
		return true
	}

	for _, indicator := range metadataPathIndicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}
	return false
}

func stripQuery(path string) string {
	before, _, found := strings.Cut(path, "?")
	if found {
		return before
	}
	return path
}

func containsAnyPathIndicator(path string, indicators []string) bool {
	for _, indicator := range indicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}
	return false
}
