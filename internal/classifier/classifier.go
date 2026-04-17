package classifier

import "strings"

type ClientClass string

const (
	Browser        ClientClass = "browser"
	CLI            ClientClass = "cli"
	PackageManager ClientClass = "package_manager"
)

var packageManagerIndicators = []string{
	"apt",
	"yum",
	"dnf",
	"pip",
	"npm",
	"cargo",
	"gem",
	"pacman",
	"apk",
}

var browserExclusions = []string{
	"curl",
	"wget",
	"python-requests",
	"apt",
	"yum",
	"dnf",
	"pip",
	"npm",
	"cargo",
	"go/",
}

func Classify(ua string) ClientClass {
	uaLower := strings.ToLower(ua)

	if containsAny(uaLower, packageManagerIndicators) {
		return PackageManager
	}

	if strings.Contains(uaLower, "mozilla") && !containsAny(uaLower, browserExclusions) {
		return Browser
	}

	return CLI
}

func IsBrowser(class ClientClass) bool {
	return class == Browser
}

func IsCLI(class ClientClass) bool {
	return class == CLI
}

func IsPackageManager(class ClientClass) bool {
	return class == PackageManager
}

func containsAny(s string, tokens []string) bool {
	for _, token := range tokens {
		if strings.Contains(s, token) {
			return true
		}
	}
	return false
}
