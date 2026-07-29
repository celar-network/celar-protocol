package fhe

// CelarFHEPrecompileAddress is the fized address of the Celar FHE precompile.
// Stock cosmos.evm precompiles occupy 0x100, 0,400, 0x800-0x807; Celar takes
// the 0x900 block
const CelarFHEPrecompileAddress = "0x0000000000000000000000000000000000000900"

// domainTag namespaces stub handles derivation. Bump on any change to the
// derivation scheme.
const domainTag = "celar.fhe.v0"

// Method names (must match abi.json)
const (
	VerifyInputMethod      = "verifyInput"
	TrivialEncryptMethod   = "trivialEncrypt"
	AddMethod              = "add"
	SubMethod              = "sub"
	LeMethod               = "le"
	LtMethod               = "lt"
	EqMethod               = "eq"
	AndMethod              = "and"
	OrMethod               = "or"
	NotMethod              = "not"
	SelectMethod           = "select"
	CastMethod             = "cast"
	AllowMethod            = "allow"
	RequestReencryptMethod = "requestReencrypt"
	RequestRevealMethod    = "requestReveal"
)

// Flat stub gas costs per op group. Real 2-D fee metering is task D4.
const (
	GasCompute  uint64 = 3_000
	GasInput    uint64 = 10_000
	GasStateful uint64 = 20_000
)

// Permission values for allow(). Mirrors ABI.md: perm ∈ {compute,
// reencryptToSelf, reveal}.
const (
	PermCompute         uint8 = 0
	PermReencryptToSelf uint8 = 1
	PermReveal          uint8 = 2
)
