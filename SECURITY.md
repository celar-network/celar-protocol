# Security policy

## Status of this software

Celar is pre-launch. Nothing in this repository is deployed with real value;
the network described in the whitepaper is not yet live. Security review of
the design is in progress, and the whitepaper discloses known limitations of
the current construction openly (see, for example, the corruption-model
mapping in section 7.1, which states the deployed confidentiality threshold
alongside the design target). A disclosed limitation is not a vulnerability
report; a bug that lets an attacker exceed what the documentation says the
system permits is.

## Reporting a vulnerability

Please do not open a public issue for a security-sensitive finding.

Use GitHub's private vulnerability reporting for this repository:
https://github.com/celar-network/celar-protocol/security/advisories/new

Alternatively, email security@celar.network.

Include what you found, how to reproduce it, and what you believe the impact
is. If you have a proof of concept, attach it privately rather than
publishing it.

## What to expect

- Acknowledgement of your report within 5 business days.
- An initial assessment and severity classification within 15 business days.
- We will keep you informed as we work on a fix and agree a disclosure date
  with you. We aim to resolve and disclose within 90 days of the report; if
  we need longer, we will say so and why.
- We will credit you in the advisory unless you prefer otherwise.

## Scope

In scope: the code in this repository — the chain node (`chain/`), the
threshold key-management service (`kms/`), the FHE backend adapter (`fhe/`),
and the contracts (`chain/contracts/`).

Out of scope: vulnerabilities in upstream dependencies (report those
upstream — cosmos/evm, zama-ai/kms, TFHE-rs — and let us know so we can track
the fix), the marketing website, and denial-of-service against development
infrastructure.

## Safe harbour

Good-faith security research conducted in accordance with this policy will
not be treated as a violation. Do not access, modify, or exfiltrate data that
is not yours, and do not test against infrastructure you do not control
without permission.

## Bounty

There is no bounty programme at this time. If one is established it will be
announced here.
