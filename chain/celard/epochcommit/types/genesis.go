package types

import "fmt"

// DefaultGenesisState is an empty archive with no bounds: a chain that has
// never keyed an epoch has no retention horizon, which is a different state
// from one whose horizon happens to be zero.
func DefaultGenesisState() *GenesisState {
	return &GenesisState{}
}

func NewGenesisState(entries []ArchiveEntry, boundsSet bool, oldest, latest uint64) *GenesisState {
	return &GenesisState{
		Entries:             entries,
		BoundsSet:           boundsSet,
		OldestRetainedEpoch: oldest,
		LatestEpoch:         latest,
	}
}

// Validate rejects any genesis that would make absence undecidable at the
// verifier. Each rule below corresponds to a verdict that would otherwise be
// wrong rather than merely missing.
func (gs *GenesisState) Validate() error {
	if !gs.BoundsSet {
		if len(gs.Entries) > 0 {
			return fmt.Errorf(
				"%d entries present with no retention bounds: every entry "+
					"would resolve as an epoch the chain never established",
				len(gs.Entries))
		}
		return nil
	}

	if gs.OldestRetainedEpoch > gs.LatestEpoch {
		return fmt.Errorf(
			"retention horizon %d is above the latest epoch %d, so every "+
				"epoch is simultaneously time-barred and never-established",
			gs.OldestRetainedEpoch, gs.LatestEpoch)
	}

	seen := make(map[[2]uint64]struct{}, len(gs.Entries))
	for i, e := range gs.Entries {
		if e.SeatRole == 0 {
			return fmt.Errorf("entry %d: %w", i, ErrInvalidSeatRole)
		}
		if e.Epoch < gs.OldestRetainedEpoch || e.Epoch > gs.LatestEpoch {
			return fmt.Errorf(
				"entry %d is for epoch %d, outside the retained range [%d, %d]: "+
					"a retained entry below the horizon reads as time-barred "+
					"while still being present",
				i, e.Epoch, gs.OldestRetainedEpoch, gs.LatestEpoch)
		}
		bz, err := e.Commitment.Marshal()
		if err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if len(bz) == 0 {
			return fmt.Errorf(
				"entry %d (epoch %d, seat %d) is empty and would be "+
					"indistinguishable from an absent one",
				i, e.Epoch, e.SeatRole)
		}
		key := [2]uint64{e.Epoch, uint64(e.SeatRole)}
		if _, dup := seen[key]; dup {
			return fmt.Errorf(
				"duplicate entry for epoch %d seat %d: import order would "+
					"decide which survives",
				e.Epoch, e.SeatRole)
		}
		seen[key] = struct{}{}
	}
	return nil
}
