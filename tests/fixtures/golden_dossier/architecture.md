# Nexus Payments Hub — Architecture Notes

**Note:** This document describes the logical and network architecture. Refer to
`sats.md` for the full component inventory and control evidence.

## Network zones

NPH operates across four segregated network zones:

1. **DMZ** — public-facing ingress only; no persistent data.
2. **Processing zone** — transaction logic; no direct internet access.
3. **Data zone** — restricted; database tier; no external connectivity.
4. **SWIFT zone** — isolated; SWIFTNet only; hardware security module.

## Trust boundaries

Three trust boundaries are enforced:

- Internet → DMZ: enforced by border firewall + WAF
- DMZ → Internal (processing zone): enforced by internal firewall
- Internal → Restricted (data and SWIFT zones): enforced by micro-segmentation

## Known integration points

The API gateway terminates client connections and forwards to the payment engine.
The payment engine writes to the customer database and dispatches to the SWIFT adapter.
FraudGuard is called synchronously before ledger commit.

Refinitiv World-Check is queried for each new counterparty (sanctions screening).

## Architecture diagram

See attached `network_diagram.png` for the full component and trust-boundary diagram.
The diagram includes components and data flows that may not be fully described in text,
including the internal audit API and its connection to the compliance data store.
