# epochcommit

Per-epoch DKG share commitments, retained in chain state so that §7.4
accountability evidence stays verifiable after a reshare has replaced every
live commitment. The KMS reads this store through ICS23; it never reads the
off-chain transcript, which does not survive the epoch it belongs to.

Store key: `epochcommit`. The name is part of the proof path the KMS
verifier checks, so it cannot change without changing that verifier.

## Encoding

`ArchivedSeatCommitment`'s field numbers are canonical. An entry is hashed in
its proto encoding under those numbers and no other canonical form exists, so
the numbers are fixed and the KMS-side reader declares the same four in the
same order.

## Regenerating

Requires `protoc` and the generator pinned to the same gogoproto version the
module depends on — a generator mismatched to its runtime marshals slightly
differently, which is exactly what canonical bytes cannot tolerate.
go install github.com/cosmos/gogoproto/protoc-gen-gocosmos@v1.7.2
GOGO=$(go list -m -f '{{.Dir}}' github.com/cosmos/gogoproto)
protoc -I proto -I "
𝐺
𝑂
𝐺
𝑂
"
−
𝐼
"
GOGO"−I"GOGO/protobuf"
gocosmos_out=plugins=interfacetype+grpc,Mgoogle/protobuf/any.proto=github.com/cosmos/cosmos-sdk/codec/types:.
proto/celar/epochcommit/v1/archive.proto
mv ./github.com/cosmos/evm/evmd/epochcommit/types/archive.pb.go epochcommit/types/
rm -rf ./github.com

The generated file is committed, so building and testing need none of this.
