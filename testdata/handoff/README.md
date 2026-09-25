# Attestation handoff vector

One document in the format the coprocessor writes and the relayer reads.

**Neither side's code defines this file.** The writer asserts it produces
exactly these bytes; the reader asserts it parses them into exactly these
values. A change to either implementation that moves the format fails here,
loudly, instead of surfacing as a rejected submission on chain with no
indication which side moved.

The same arrangement pins the attestation preimage and the transcript
endorsement digest, and it has caught two real disagreements between these
languages: JSON HTML-escaping on one, field packing on the other. Both would
have been silent.

The values are deliberately patterned rather than realistic — repeated bytes
make a width error visible by eye. What is being pinned is the encoding, not
the content: field names, field order, unprefixed lowercase hex, and the
integers as JSON numbers rather than strings.
