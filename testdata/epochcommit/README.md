# epochcommit export fixture

`export-two-epochs.json` is the `epochcommit` section of a genesis export, taken
from a single-validator devnet that ran to height 3 and was then exported. The
values therefore came out of the module's own encode/store/decode path rather
than from a hand-written document.

It holds two epochs with **different commitments for the same seat**, which is
what makes it useful: the regression it serves exists to show that epoch-N
evidence still verifies after epoch N+1 has replaced every live commitment, and
a single-epoch fixture would pass that test without exercising it.

Horizons are set far in the future on purpose. With a near horizon the block
sweep would prune the archive while the node was running and the export would
be empty for reasons unrelated to what the fixture is demonstrating.

## Regenerating

Build the node, generate a one-validator devnet, patch this section into its
genesis, start it briefly, then export and take `app_state.epochcommit`. The
node's export writes two log lines before the JSON.
