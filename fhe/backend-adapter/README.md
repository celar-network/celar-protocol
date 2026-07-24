# backend-adapter — THE FROZEN SEAM

Handle-based precompile ABI (§16). Held FIXED and backend-agnostic from M1.
Both Zama TFHE-rs/fhEVM and OpenFHE CGGI sit behind this identical interface.
Do NOT let application code bind to a specific backend — the decision must stay
node-level reversible. Bake-off criteria: docs/celar-backend-bakeoff-spec.md
