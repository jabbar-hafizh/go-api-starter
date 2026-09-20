// Package appversion decides whether a client build is still allowed to run.
//
// Mobile builds live on devices for months and cannot be forced to update, so
// the server has to be able to tell one it has fallen too far behind.
package appversion

import (
	"strconv"
	"strings"
)

// Gate holds the minimum build per platform. An empty minimum disables the
// check for that platform.
type Gate struct {
	minIOS         string
	minAndroid     string
	upgradeMessage string
}

// Decision is what a client is told about itself.
type Decision struct {
	MinSupportedVersion string
	ForceUpgrade        bool
	UpgradeMessage      string
}

// NewGate builds the version gate.
func NewGate(minIOS, minAndroid, upgradeMessage string) *Gate {
	return &Gate{minIOS: minIOS, minAndroid: minAndroid, upgradeMessage: upgradeMessage}
}

// Decide answers for one client. An unknown platform or an unparseable version
// is never forced to upgrade: locking someone out over a header this server
// failed to read would be worse than letting an old build through.
func (g *Gate) Decide(platform, version string) Decision {
	minimum := g.minimumFor(platform)
	d := Decision{MinSupportedVersion: minimum}

	if minimum == "" || version == "" {
		return d
	}
	if Compare(version, minimum) < 0 {
		d.ForceUpgrade = true
		d.UpgradeMessage = g.upgradeMessage
	}
	return d
}

func (g *Gate) minimumFor(platform string) string {
	switch strings.ToLower(platform) {
	case "ios":
		return g.minIOS
	case "android":
		return g.minAndroid
	default:
		return ""
	}
}

// Compare orders dotted numeric versions: -1, 0 or 1. Missing components count
// as zero, so "1.2" and "1.2.0" are the same build. A component that is not a
// number compares as zero rather than failing, because a malformed header must
// not decide whether someone can use the app.
func Compare(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")

	for i := range max(len(left), len(right)) {
		if d := component(left, i) - component(right, i); d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

func component(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	// Drop any suffix such as "-beta" so 1.2.3-beta compares as 1.2.3.
	value := parts[i]
	if idx := strings.IndexAny(value, "-+"); idx >= 0 {
		value = value[:idx]
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return n
}
