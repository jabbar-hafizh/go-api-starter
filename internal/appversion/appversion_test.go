package appversion_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/appversion"
)

func TestCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.10.0", "1.9.0", 1},
		// Missing components count as zero, so these are the same build.
		{"1.2", "1.2.0", 0},
		{"1", "1.0.0", 0},
		{"1.2.3", "1.2", 1},
		// A suffix is dropped, so a beta of a build compares as that build.
		{"1.2.3-beta", "1.2.3", 0},
		{"1.2.3+build9", "1.2.3", 0},
		// Garbage counts as zero rather than failing: a malformed header must
		// not decide whether someone can use the app.
		{"", "1.0.0", -1},
		{"not-a-version", "1.0.0", -1},
		{"1.x.3", "1.0.3", 0},
	}

	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, appversion.Compare(tt.a, tt.b))
		})
	}
}

func TestDecide(t *testing.T) {
	t.Parallel()

	gate := appversion.NewGate("2.0.0", "3.1.0", "Update to continue.")

	tests := []struct {
		name             string
		platform, client string
		wantMin          string
		wantForce        bool
	}{
		{"ios below minimum", "ios", "1.9.9", "2.0.0", true},
		{"ios at minimum", "ios", "2.0.0", "2.0.0", false},
		{"ios above minimum", "ios", "2.4.0", "2.0.0", false},
		{"android below minimum", "android", "3.0.9", "3.1.0", true},
		{"android above minimum", "android", "3.1.1", "3.1.0", false},
		{"platform case is ignored", "iOS", "1.0.0", "2.0.0", true},
		// Web is not gated, and neither is anything unrecognised: locking
		// someone out over a header this server failed to read would be worse
		// than letting an old build through.
		{"web is not gated", "web", "0.0.1", "", false},
		{"unknown platform", "toaster", "0.0.1", "", false},
		{"no platform", "", "1.0.0", "", false},
		{"no version", "ios", "", "2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := gate.Decide(tt.platform, tt.client)
			require.Equal(t, tt.wantMin, got.MinSupportedVersion)
			require.Equal(t, tt.wantForce, got.ForceUpgrade)
			if tt.wantForce {
				require.Equal(t, "Update to continue.", got.UpgradeMessage)
			} else {
				require.Empty(t, got.UpgradeMessage)
			}
		})
	}
}

// An empty minimum turns the check off for that platform.
func TestEmptyMinimumDisablesTheGate(t *testing.T) {
	t.Parallel()

	gate := appversion.NewGate("", "", "Update.")

	for _, platform := range []string{"ios", "android", "web"} {
		got := gate.Decide(platform, "0.0.1")
		require.False(t, got.ForceUpgrade)
		require.Empty(t, got.MinSupportedVersion)
	}
}
