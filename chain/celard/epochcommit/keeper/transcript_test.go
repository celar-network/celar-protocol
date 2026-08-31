package keeper_test

import "testing"

func TestTranscriptDigestRoundTrips(t *testing.T) {
	k, ctx := newKeeper(t)
	if err := k.SetTranscriptDigest(ctx, 5, "deadbeef"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := k.GetTranscriptDigest(ctx, 5)
	if !ok || got != "deadbeef" {
		t.Fatalf("round trip lost the digest: %q ok=%v", got, ok)
	}
}

// Absence must stay distinguishable from a recorded value: a submission
// chaining from an unknown epoch has to be refusable, not silently treated
// as chaining from nothing.
func TestUnknownAndEmptyDigestsAreDistinguishable(t *testing.T) {
	k, ctx := newKeeper(t)
	if _, ok := k.GetTranscriptDigest(ctx, 99); ok {
		t.Fatal("an epoch that was never recorded reports as present")
	}
	if err := k.SetTranscriptDigest(ctx, 1, ""); err == nil {
		t.Fatal("wrote an empty digest, which reads as absence")
	}
	if _, ok := k.GetTranscriptDigest(ctx, 1); ok {
		t.Fatal("the refused write left something behind")
	}
}
