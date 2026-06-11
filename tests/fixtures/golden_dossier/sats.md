# Security Architecture & Technical Specification — Nexus Payments Hub

**Classification:** Internal — Restricted  
**System:** Nexus Payments Hub  
**Owner:** Payments Engineering  
**Version:** 3.1

---

## 1. System Overview

Nexus Payments Hub (NPH) is the bank's core payment-processing platform. It orchestrates
real-time and batch payment flows between clients, internal ledgers, third-party settlement
networks, and the SWIFT gateway.

### 1.1 Business criticality

NPH is classified as Critical ICT (DORA Tier 1). Any outage exceeding 4 hours triggers
regulatory reporting under DORA Article 19. The system processes €2.4B daily across
18 payment schemes.

### 1.2 Deployment environment

NPH runs on-premises in the bank's primary and DR data centers. Production workloads
are containerized (Kubernetes 1.30). No public-cloud dependencies for core transaction
processing.

---

## 2. Component Inventory

### 2.1 Public-facing API gateway

- **Component:** `nexus-api-gateway`
- **Technology:** Kong Gateway 3.6 (custom plugin: JWT validation, PCI-DSS header enforcement)
- **Exposure:** Internet-facing (DMZ zone)
- **Protocols:** HTTPS/TLS 1.3 only
- **Functions:** Authentication, rate limiting (500 req/s per client), request routing

### 2.2 Payment processing engine

- **Component:** `payment-engine`
- **Technology:** Java 21, Spring Boot 3.2
- **Exposure:** Internal (processing zone)
- **Functions:** Transaction validation, ISO 20022 message parsing, ledger debit/credit,
  idempotency key management

### 2.3 Customer data store

- **Component:** `customer-db`
- **Technology:** PostgreSQL 16.3
- **Exposure:** Restricted (data zone)
- **Data classification:** Confidential — PII, payment data (PAN, IBAN), GDPR-applicable
- **Encryption at rest:** AES-256 (LUKS)

### 2.4 SWIFT messaging adapter

- **Component:** `swift-adapter`
- **Technology:** SWIFTNet Link 7.5, in-house Java wrapper
- **Exposure:** Restricted (SWIFT zone — isolated)
- **Functions:** MT/MX message formatting, SWIFTNet authentication, non-repudiation

### 2.5 FraudGuard AI module

- **Component:** `fraudguard-ai`
- **Technology:** Internal ML inference service (ONNX Runtime, Python 3.12)
- **Exposure:** Internal (processing zone)
- **Model type:** Supervised classification — transaction fraud detection
- **GenAI:** No (classical ML, not an LLM or generative model)
- **PII access:** Yes — scores are derived from behavioral and transaction history

---

## 3. Data Flows

### 3.1 Client → API gateway → Payment engine

Payment initiation requests traverse from the internet through the DMZ into the
internal processing zone. This flow crosses two trust boundaries.

- **Source:** Internet (client)
- **Destination:** `nexus-api-gateway` → `payment-engine`
- **Data:** Payment orders (amount, IBAN pair, reference)
- **Encryption in transit:** TLS 1.3 (confirmed)
- **Trust boundary crossed:** Internet → DMZ, DMZ → Internal

### 3.2 Payment engine → Customer DB

Transaction state and customer lookup queries.

- **Source:** `payment-engine`
- **Destination:** `customer-db`
- **Data:** Customer PII, IBAN, transaction records
- **Encryption in transit:** TLS (internal mTLS)
- **Trust boundary crossed:** Internal → Restricted (Data zone)

### 3.3 Payment engine → SWIFT adapter

Outbound SWIFT messages for correspondent banking and cross-border payments.

- **Source:** `payment-engine`
- **Destination:** `swift-adapter`
- **Data:** ISO 20022 MX payment instructions, SWIFT MT messages
- **Encryption in transit:** SWIFTNet PKI (end-to-end)
- **Trust boundary crossed:** Internal → SWIFT zone

### 3.4 FraudGuard scoring flow

Each payment request is scored before ledger commit.

- **Source:** `payment-engine`
- **Destination:** `fraudguard-ai`
- **Data:** Transaction features (anonymized behavioral features + amount + counterparty hash)
- **Encryption in transit:** Internal mTLS (confirmed)
- **Trust boundary crossed:** No (both in processing zone)

---

## 4. Third-Party Dependencies

### 4.1 SWIFT (SWIFTNet)

- **Classification:** Critical ICT third party (DORA)
- **Service:** Interbank messaging network
- **Exit plan:** SEPA Instant fallback + bilateral correspondent agreements (18-month transition)
- **Concentration risk:** Yes — single network for cross-border MX flows

### 4.2 Refinitiv World-Check

- **Classification:** Important ICT third party
- **Service:** Sanctions screening (AML/CFT)
- **Data processed:** Customer name, date of birth, nationality, IBAN (query)
- **Exit plan:** ACAMS alternative licensed; 6-week migration estimated
- **Concentration risk:** No

---

## 5. Security Controls

### 5.1 Access controls

- MFA enforced for all administrative access to production systems (YubiKey hardware tokens)
- RBAC via internal IAM; privileged access reviewed quarterly
- Admin console (`nexus-admin`) requires VPN + MFA + just-in-time approval

### 5.2 Network segmentation

Four-zone model: Internet → DMZ → Internal → Restricted (Data/SWIFT). Firewalls at
each boundary; default-deny between zones; east-west traffic inspected by internal
IDS (Suricata 7.0).

### 5.3 Vulnerability management

Quarterly internal penetration testing (last: Q1 2026, no critical findings open).
Dependency scanning via Dependabot and Trivy in CI pipeline.
Container image scanning on every build.

### 5.4 Logging and monitoring

Centralized SIEM (Splunk Enterprise). Payment API audit logs retained 7 years (PSD2).
FraudGuard model predictions logged with feature hash for audit. Real-time alerting on
anomalous transaction volumes.

### 5.5 Resilience

Active-passive DR (RPO 30 min, RTO 4 h). Chaos engineering exercises run quarterly.
Degraded-mode fallback: batch settlement when real-time fails.
