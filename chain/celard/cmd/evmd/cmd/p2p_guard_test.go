package cmd

import (
	"strings"
	"testing"

	cmtcfg "github.com/cometbft/cometbft/config"
)

// The guard is a predicate over the effective config, so it is testable
// without standing a node up. That is deliberate: a guard whose only test is
// "the devnet still starts" passes for as long as the devnet generator keeps
// writing the setting, which is the very thing this stopped relying on.

func TestP2PGuard_AllowsTheDisabledDefault(t *testing.T) {
	cfg := cmtcfg.DefaultConfig()
	if cfg.P2P.LibP2PConfig.Enabled {
		// If upstream ever flips this default, the guard becomes load-bearing
		// for every operator rather than a backstop, and that is worth
		// discovering from a failing test rather than from an advisory.
		t.Fatal("upstream now enables the experimental transport by default; re-read the guard's reasoning")
	}
	if err := refuseExperimentalP2PTransport(cfg); err != nil {
		t.Fatalf("the shipped default must start: %v", err)
	}
}

func TestP2PGuard_RefusesWhenEnabled(t *testing.T) {
	cfg := cmtcfg.DefaultConfig()
	cfg.P2P.LibP2PConfig.Enabled = true

	err := refuseExperimentalP2PTransport(cfg)
	if err == nil {
		t.Fatal("a node configured to run the experimental transport must not start")
	}
	// The message has to name the setting and the file. An operator meeting a
	// bare refusal edits the wrong thing, or reads a correct refusal as a bug
	// and works around it.
	for _, want := range []string{"p2p.libp2p", "config.toml", "false"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal should name %q so it is actionable; got: %v", want, err)
		}
	}
}

func TestP2PGuard_NilConfigDoesNotPanic(t *testing.T) {
	// Commands that run before a config is loaded reach this with nil. A guard
	// that panics on the path it does not care about is worse than no guard.
	if err := refuseExperimentalP2PTransport(nil); err != nil {
		t.Fatalf("a nil config is not a misconfiguration: %v", err)
	}
}
