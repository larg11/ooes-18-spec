# OOES-18: An Open Deterministic Evidence Schema for EU Regulation 2024/3015 and French DELTA IE (H1) Pre-Clearance

**Version:** 1.1.0  
**Date:** October 2026  
**Status:** Open technical specification  
**Author:** Mohammad Anwaruzzaman  
**ORCID:** 0009-0004-5697-7634  
**Affiliation:** Founder & Chief Architect, First Order Technologies SAS (Paris, France - in incorporation)  
**Companion paper:** DS-PR412, SSRN #6661398, DOI 10.2139/ssrn.6661398  
**Reference engine:** `@foin/crisis-engine`  
**License:** CC-BY-4.0 for this document; Apache-2.0 for schemas, test vectors, trust store, and reference verifier

---

## Abstract

Cross-border manufacturing orders expose importers to a structural epistemic gap. Under a typical 30% advance telegraphic transfer, capital is released on Day 0 (`t_0`) against assertions, while the physical truth of production, origin, custody, and documentary title becomes observable only at destination arrival (`t_75`). The companion paper DS-PR412 (SSRN #6661398, DOI 10.2139/ssrn.6661398) provides a practice-derived dataset of 412 first manufacturing orders placed by small founder-led firms with overseas factories in six countries between 2011 and 2024. The dataset is author-coded; 59 of the 412 orders are coded as adverse (14.32%, approximately one in seven). The 75-day contract-to-arrival window used in this specification is the reference workflow assumption, not a reported DS-PR412 mean. Existing post-presentation document examination operates at `t_45` to `t_60`, after capital is deployed and cargo has sailed, and relies on probabilistic extraction without a physical floor linkage. Consortium trade-finance blockchains addressed shared-ledger governance rather than local origin capture and duplicate-pledge privacy.

This document specifies OOES-18, an open deterministic evidence schema for pre-clearance. OOES-18 is organized as five functional layers and exactly eighteen evidence slots. Each slot carries one of three epistemic states in a bounded Kleene lattice: `UNKNOWN`, `ASSERTED`, or `CORROBORATED`. A slot is `CORROBORATED` only when its payload is structurally valid, cryptographically sealed, and independently attested by an accredited third party or authority whose Ed25519 signature verifies against a public key in the relying party's trust store. Two deterministic release gates evaluate both epistemic-state predicates and cross-slot reconciliation predicates: `GATE_01_DEPOSIT_PRE_WIRE` for the Day-0 30% T/T advance and `GATE_02_BALANCE_AND_PRE_CLEARANCE` for pre-shipment, UCP 600 presentation, and French DELTA IE H1 pre-clearance. The cryptographic protocol uses RFC 8785 JSON Canonicalization, RFC 5869 HKDF-SHA256 per-slot key isolation, HMAC-SHA256 slot digests, AES-256-GCM authenticated encryption, and Ed25519 attestation signatures over the payload hash. A salted blind-index protocol enables cross-lender duplicate-pledge detection without sharing tenant keys or commercial plaintext.

The reference verifier has no runtime dependencies beyond Node built-ins and is accompanied by a deterministically generated test vector, `CASCADE-2026-9F4A2C`, with 8 `CORROBORATED`, 4 `ASSERTED`, and 6 `UNKNOWN` slots. The default vector correctly halts both gates: `GATE_01` on `L2.S05` and `L2.S06`, and `GATE_02` on `L2.S05`, `L4.S11`, `L4.S12`, `L5.S14`, `L5.S15`, and `L5.S16`. A single-byte mutation of the `L3.S09` laboratory payload causes deterministic demotion to `UNKNOWN` and a `GATE_02` hard stop. The specification closes with the Oracle Boundary Theorem: cryptographic sealing and attestation prove capture provenance, tenant isolation, and post-capture immutability, but physical ground truth requires the `ASSERTED` to `CORROBORATED` transition through independent accredited inspection and geofenced telemetry.

**Keywords:** forced labour regulation, EU 2024/3015, DELTA IE H1, UCP 600, ISBP 821, trade finance, customs valuation, TARIC, deterministic verification, RFC 8785, RFC 5869, blind index, duplicate pledge.

---

## 1. Empirical Problem Statement

### 1.1 The 75-day epistemic verification gap

Let `t_0` denote the timestamp at which the importer releases a 30% advance telegraphic transfer. Let `t_75` denote the timestamp at which the cargo arrives at the destination port and the physical facts become inspectable. This specification models a 75-day reference window:

```text
Delta_epistemic = t_75 - t_0 = 75 days
```

The 75-day figure is a workflow assumption used to size the exposure. It is not presented as a mean reported by DS-PR412.

During this interval, the importer's capital is exposed to a dossier that has not been independently corroborated. The exporter may be honest, the factory may be the audited factory, the container may be sealed at the declared site, and the laboratory may have tested the declared batch. None of these propositions is established at `t_0`. They are asserted.

The economic exposure is not limited to the 30% advance. A documentary credit may be issued for the balance, a credit insurer may underwrite the receivable, and a bank may finance the shipment. Each participant prices the same unresolved epistemic gap, often without a shared collision-resistant view of whether the same shipment has already been pledged elsewhere.

### 1.2 DS-PR412 quantitative anchor

DS-PR412 is *First-Order Manufacturing Failure in Small-Firm International Sourcing: A Practice-Derived Cascade Model from 412 Cases (DS-PR412, 2011–2024)*, SSRN #6661398, DOI 10.2139/ssrn.6661398. It is a two-page, practice-derived working paper. The dataset covers 412 first manufacturing orders placed by small founder-led firms with overseas factories in Bangladesh, Vietnam, China, India, South Korea, and Thailand across five product categories between 2011 and 2024. The dataset is author-coded, and the paper states that an inter-rater reliability review is in progress.

| Measure | Value |
| :--- | :--- |
| Sample size | 412 first orders |
| Adverse event count | 59 |
| Adverse event rate | **14.32%** (59/412) |
| Approximate incidence | 1 in 7 |
| Reference contract-to-arrival window | 75 days (workflow assumption, not a DS-PR412 mean) |
| Countries | Bangladesh, Vietnam, China, India, South Korea, Thailand |
| Product categories | 5 |
| Period | 2011-2024 |

The 14.32% figure is descriptive of the author-coded dataset, not a causal estimate or a population parameter. For OOES-18 purposes, the adverse events are grouped into four operational families; this grouping is the specification's, not a classification claimed by DS-PR412:

1. **Quality defects.** The delivered goods do not meet the contracted technical specification, fiber composition, dimensional tolerance, or colorfastness baseline.
2. **Unauthorized shadow subcontracting.** Production is routed to a tier-1 or tier-2 unit that is not the audited factory and is not disclosed in the purchase order, capacity attestation, or origin statement.
3. **Late or forged shipping documents.** The bill of lading, certificate of origin, inspection certificate, or seal record does not truthfully describe the shipment, the vessel, the container, or the loading date.
4. **TARIC and origin misclassification.** The declared commodity code, preferential origin, or customs value does not match the goods, generating duty reassessment, preference recovery, or penalties.

OOES-18 does not attempt to predict these events. It makes the evidence state explicit and forces a deterministic halt when the evidence required to underwrite the event is absent or merely asserted.

### 1.3 Failure of legacy post-presentation examination

Legacy trade-finance document examination operates at `t_45` to `t_60`, after the advance has been wired and the vessel has sailed. It has three structural limits.

First, it is retrospective. A discrepancy discovered at `t_45` cannot recover the Day-0 advance; it can only reprice or reject the balance.

Second, it is probabilistic. OCR, VLM layout parsing, and LLM extraction produce candidate strings with confidence scores. A confidence score is not an epistemic state. A 0.97 extraction confidence for a container number does not establish that the container was stuffed at the declared factory or that the same container was not pledged to a second lender.

Third, it lacks physical floor linkage. A PDF bill of lading can be internally consistent and still describe a different container, a different loading port, or a different factory. Post-presentation examination compares documents to documents, not documents to physical capture events.

### 1.4 Failure of consortium trade-finance blockchains

Marco Polo, we.trade, and TradeLens attempted to improve trade-finance coordination through shared ledgers. Their commercial difficulties are instructive.

- **Governance friction.** Banks, carriers, and corporates could not agree on who controls the network, who admits members, and who bears liability for a wrong attestation.
- **Onboarding chicken-and-egg.** A network is valuable only when both counterparties are members. A bank cannot force its SME importer and its Bangladesh supplier to join the same consortium.
- **Wrong layer of the stack.** Placing commercial metadata on a shared ledger does not solve local origin capture. A ledger can record that a factory asserted a production date. It cannot establish that the production occurred at the declared geofence.
- **Privacy versus duplicate detection.** Lenders need to know whether a shipment is already pledged, but they cannot publish commercial terms. A plaintext shipment registry violates confidentiality; a per-bank silo cannot detect cross-bank duplication.

OOES-18 is deliberately narrower than a consortium ledger. It standardizes (i) the evidence object, (ii) the epistemic state, (iii) the deterministic gate, and (iv) a salted blind-index collision token. It can operate over ordinary APIs, object storage, and bank-owned infrastructure.

### 1.5 Design requirements

| ID | Requirement |
| :--- | :--- |
| R1 | Every release decision MUST be a pure, total, deterministic function of the canonical dossier. |
| R2 | Probabilistic extraction MUST be confined to an untrusted staging area; no confidence score may enter the release path. |
| R3 | Mandatory evidence MUST be independently corroborated, not merely self-asserted. |
| R4 | Cross-slot semantic contradictions MUST halt release even when every seal is cryptographically valid. |
| R5 | Duplicate-pledge detection MUST work across lenders without sharing tenant keys or commercial plaintext. |
| R6 | The protocol MUST be implementable with standard cryptographic primitives and no proprietary ledger. |

---

## 2. The Five-Layer, Eighteen-Slot Data Model

### 2.1 Dossier definition

An OOES-18 dossier is the tuple:

```text
D = (tenant_id, dossier_id, t_ref, salt_HKDF, {s_1, ..., s_18}, B)
```

where `t_ref` is the deterministic reference timestamp, `salt_HKDF` is a 16-byte dossier salt, each `s_i` is a slot envelope, and `B` is the salted blind-index record. The canonical byte representation of any payload is `UTF8(JCS(payload))`, as defined in Section 3.1.

### 2.2 The 18 slots

| Layer | Slot ID | Canonical name | Required semantic payload fields |
| :--- | :--- | :--- | :--- |
| L1 Contract | `L1.S01_PURCHASE_ORDER` | Executed purchase order | `po_number`, `buyer_eori`, `supplier_id`, `incoterms_2020`, `currency`, `total_amount`, `total_units`, `unit_price`, `delivery_window_end` |
| L1 Contract | `L1.S02_TECH_PACK` | Technical specification and BoM | `tech_pack_id`, `sku_code`, `product_description`, `fiber_composition`, `gsm_weight`, `dimensional_tolerance_pct`, `bom_hash` |
| L1 Contract | `L1.S03_GOLDEN_SAMPLE` | Physical counter-sample baseline | `sample_seal_tag`, `physical_sha256_manifest`, `approved_by_buyer_id`, `approved_at`, `colorfastness_baseline` |
| L2 Entity | `L2.S04_SUPPLIER_KYB` | Legal entity and factory geolocation | `legal_name`, `tax_registration_id`, `country_iso2`, `factory_lat`, `factory_lon`, `beneficial_owners_verified` |
| L2 Entity | `L2.S05_REGISTRY_STANDING` | Trade registry and forced-labour log | `registry_authority`, `membership_id`, `rex_number`, `eu_2024_3015_screening_status`, `sanctions_clear` |
| L2 Entity | `L2.S06_CAPACITY_ATTESTATION` | Line allocation and subcontracting ban | `allocated_lines`, `daily_output_capacity_units`, `subcontracting_authorized`, `tier2_mill_tax_ids` |
| L3 Factory | `L3.S07_PRODUCTION_PHOTOS` | Hardware-geotagged inline media | `media_count`, `capture_device_pubkey_fp`, `exif_gps_lat`, `exif_gps_lon`, `max_distance_from_s04_meters`, `merkle_media_root` |
| L3 Factory | `L3.S08_INLINE_AQL` | ISO 2859-1 inline/DUPRO inspection | `inspector_agency`, `iso17020_accreditation_id`, `aql_standard`, `sample_size`, `critical_defects`, `major_defects`, `max_allowed_major`, `result` |
| L3 Factory | `L3.S09_LAB_CERTIFICATE` | ISO/IEC 17025 chemical and DPP test | `lab_name`, `iso17025_accreditation_id`, `report_number`, `reach_annex_xvii_compliant`, `azo_dyes_ppm`, `measured_cotton_pct`, `espr_dpp_uid` |
| L4 Title | `L4.S10_BOLT_SEAL` | ISO 17712 container stuffing seal | `seal_serial_number`, `iso17712_clause_6_compliant`, `container_number`, `stuffing_location_type`, `stuffing_lat`, `stuffing_lon`, `sealed_at` |
| L4 Title | `L4.S11_BILL_OF_LADING` | Clean on-board transport document | `bl_number`, `scac_code`, `carrier_name`, `vessel_name`, `vessel_imo`, `port_of_loading_unlocode`, `port_of_discharge_unlocode`, `container_number`, `shipped_on_board_date`, `gross_weight_kg`, `carton_count`, `clean_on_board` |
| L4 Title | `L4.S12_CERTIFICATE_OF_ORIGIN` | Origin proof: chamber certificate or REX statement | `coo_number`, `proof_type`, `origin_regime`, `preference_programme`, `issuing_authority`, `origin_criterion`, `country_of_origin_iso2`, `exporter_rex_id`, `tier2_yarn_origin_iso2`, `tier3_raw_material_origin_iso2` |
| L4 Title | `L4.S13_SETTLEMENT_INSTRUMENT` | SWIFT MT700 or MT103 settlement | `instrument_type`, `issuing_bank_bic`, `advising_bank_bic`, `lc_number`, `amount`, `currency`, `latest_shipment_date`, `expiry_date` |
| L5 Customs | `L5.S14_LANDED_VALUATION` | Incoterms 2020 customs valuation | `invoice_number`, `invoice_date`, `fob_value_eur`, `international_freight_eur`, `insurance_eur`, `cif_customs_value_eur`, `valuation_method` |
| L5 Customs | `L5.S15_DUTY_CALCULATION` | 10-digit EU TARIC and fiscal schedule | `taric_10_code`, `preference_code`, `mfn_duty_rate_pct`, `preferential_duty_rate_pct`, `calculated_duty_eur`, `import_vat_rate_pct`, `calculated_vat_eur` |
| L5 Customs | `L5.S16_PSI_REPORT` | Pre-shipment loading reconciliation | `psi_agency`, `certificate_number`, `verified_carton_count`, `verified_units_count`, `verified_gross_weight_kg`, `verified_seal_serial` |
| L5 Customs | `L5.S17_GPS_TELEMETRY` | Origin-to-port geofence chain | `origin_geofence_pass`, `transit_corridor_id`, `port_gate_in_timestamp`, `port_unlocode`, `hardware_tpm_quote_hash` |
| L5 Customs | `L5.S18_AUDIT_SIGNATURE` | Deterministic dossier state root | `dossier_merkle_root`, `slot_digests_map_hash`, `kernel_version`, `reviewer_eidas_key_id`, `signed_at` |

Each slot envelope has exactly seven members: `slot_id`, `layer`, `state`, `payload`, `seal`, `attestation`, and `fault_codes`. The JSON Schema in `schema/ooes-18.schema.json` closes every object with `additionalProperties: false`. In `S12`, `coo_number` carries the certificate number for a chamber certificate or the statement number for a REX statement; `proof_type` and `origin_regime` determine which regime applies.

### 2.3 The Kleene epistemic lattice

The state space is a bounded chain aligned with Kleene's strong three-valued logic:

```text
E = {UNKNOWN = 0, ASSERTED = 1, CORROBORATED = 2}
UNKNOWN < ASSERTED < CORROBORATED
```

The lattice operations are the usual minimum and maximum on the chain:

```text
x meet y = min(x, y)
x join y = max(x, y)
```

The epistemic interpretation is:

- **UNKNOWN (0).** The payload is missing, unsubmitted, expired past `valid_until < t_ref`, structurally invalid against the JSON Schema, or fails HMAC/GCM authentication. It is never coerced to a truthy default. Any mandatory slot in UNKNOWN triggers a hard stop.
- **ASSERTED (1).** The payload is structurally valid and signed or uploaded by an interested first or second party with capture provenance. It may be a truthful self-declaration. It is still not independently corroborated.
- **CORROBORATED (2).** The payload is structurally valid, cryptographically sealed, and independently attested by an accredited third-party oracle or authority: an ISO/IEC 17025 laboratory, an ISO/IEC 17020 inspection agency, a sovereign customs or trade registry API, a carrier electronic bill of lading registry, or a bank with a verifiable accreditation identifier. The attestation MUST carry a valid Ed25519 signature over the payload hash, MUST be non-expired at `t_ref`, and MUST use a public key present in the relying party's trust store for that authority and accreditation identifier. A tenant-controlled HMAC is not sufficient.

### 2.4 Promotion and demotion transition function

Let `Sigma_ev` be the set of evidence events:

```text
Sigma_ev = {CAPTURE, ATTEST_ACCREDITED, SEAL_OK, SEAL_MISMATCH, ATTEST_EXPIRED}
```

The transition function `delta : E x Sigma_ev -> E` is:

| From | Event | To | Condition |
| :--- | :--- | :--- | :--- |
| UNKNOWN | CAPTURE | ASSERTED | Payload is schema-valid, sealed, and uploaded by a party with provenance |
| ASSERTED | ATTEST_ACCREDITED | CORROBORATED | Independent accredited attestation verifies under a trusted Ed25519 key and is valid at `t_ref` |
| any state | SEAL_OK | unchanged | Recomputed HMAC-SHA256 and AES-GCM authentication succeed |
| CORROBORATED | SEAL_MISMATCH | UNKNOWN | Recomputed HMAC-SHA256 or AES-GCM authentication fails |
| CORROBORATED | ATTEST_EXPIRED | UNKNOWN | `attestation.expires_at < t_ref` |
| ASSERTED | SEAL_MISMATCH | UNKNOWN | Same integrity failure |
| ASSERTED | ATTEST_EXPIRED | UNKNOWN | Same expiry failure |
| UNKNOWN | CAPTURE | UNKNOWN | Any structural or cryptographic validation failure |

Promotion is monotonic only when cryptographic integrity holds. Demotion is a mandatory security override: a single byte mutation, an expired attestation, or a failed GCM tag forces `UNKNOWN` regardless of the declared state.

**Formal demotion rule.** If

```text
HMAC-SHA256(K_slot, UTF8(JCS(payload))) != seal.hmac_sha256
```

or

```text
attestation.expires_at < t_ref
```

or

```text
Ed25519Verify(attester_public_key, attestation_message) = false
```

or the attester key is absent from the trust store, then the runtime kernel MUST set the effective state of `s_i` to `UNKNOWN` and emit `ERR_SEAL_INTEGRITY_FAILURE`, `ERR_ATTESTATION_EXPIRED`, `ERR_ATTESTATION_SIGNATURE_INVALID`, or `ERR_ATTESTATION_UNTRUSTED` as applicable.

### 2.5 Gate equations

Let `sigma(s)` be the effective state after seal verification and demotion. Let `M_G1` and `M_G2` be the mandatory slot sets.

#### GATE_01_DEPOSIT_PRE_WIRE

```text
M_G1 = {S01, S02, S03, S04, S05, S06}
```

The gate returns READY if and only if:

```text
(forall s in M_G1: sigma(s) = CORROBORATED)
and seal_verify(s) = true
and S05.sanctions_clear = true
and S05.eu_2024_3015_screening_status = "CLEAR"
and S06.subcontracting_authorized = false
and S06.daily_output_capacity_units > 0
```

Otherwise it returns HARD_STOP with the enumerated halt reasons.

#### GATE_02_BALANCE_AND_PRE_CLEARANCE

```text
M_G2_core = {S01, S02, S03, S04, S07, S08, S09, S10}
M_G2_rec  = {S05, S11, S12, S14, S15, S16}
M_G2      = M_G2_core union M_G2_rec  (14 slots)
```

The gate returns READY if and only if all state predicates hold and all reconciliation predicates `Phi_G2` hold:

```text
(forall s in M_G2: sigma(s) = CORROBORATED and seal_verify(s))
```

with:

```text
Phi_G2:
  haversine(S04.factory_lat/lon, S07.exif_gps_lat/lon) <= 500 m
  if S10.stuffing_location_type = "FACTORY":
      haversine(S04.factory_lat/lon, S10.stuffing_lat/lon) <= 500 m
  if S10.stuffing_location_type = "PORT":
      G2_GEOFENCE_S04_S10 = NOT_EVALUATED
  S08.result = "PASS"
  S08.critical_defects = 0
  S08.major_defects <= S08.max_allowed_major
  S09.reach_annex_xvii_compliant = true
  S09.azo_dyes_ppm < 30
  abs(S09.measured_cotton_pct - 100) <= 3.0
  S10.container_number = S11.container_number
  S11.bl_number starts with S11.scac_code
  S10.container_number starts with S11.scac_code
  S11.clean_on_board = true
  S04.country_iso2 = S12.country_of_origin_iso2
  if S12.origin_criterion = "WO":
      S12.tier2_yarn_origin_iso2 = S12.country_of_origin_iso2
      S12.tier3_raw_material_origin_iso2 = S12.country_of_origin_iso2
  if S12.origin_criterion in {"CC", "CTH"}: pass
  if S12.proof_type = "REX_STATEMENT":
      S12.origin_regime = "PREFERENTIAL"
      S12.exporter_rex_id != null
      S05.rex_number = S12.exporter_rex_id
  if S12.proof_type = "CHAMBER_CERTIFICATE":
      S12.origin_regime = "NON_PREFERENTIAL"
      REX consistency is not evaluated
  abs((S14.fob_value_eur + S14.international_freight_eur + S14.insurance_eur)
      - S14.cif_customs_value_eur) <= 0.01
  S15.taric_10_code matches ^[0-9]{10}$
```

The Haversine distance uses the mean Earth radius 6,371,008.8 m.

Port-side stuffing is legitimate. When `S10.stuffing_location_type = "PORT"`, the factory geofence does not apply and `G2_GEOFENCE_S04_S10` is `NOT_EVALUATED`; a future extension can add a port-coordinate geofence. The rule prevents the specification from claiming factory-site stuffing when the container was actually loaded at the port.

**Source-corroboration invariant.** A semantic check is evaluated only when every slot in its `source_slots` set has effective state `CORROBORATED`. If any source is `ASSERTED` or `UNKNOWN`, the check returns `NOT_EVALUATED` and cannot contribute a `PASS`. This ensures that a gate never relies on data it does not require.

### 2.6 Enumerated halt reasons

| Code | Meaning |
| :--- | :--- |
| `ERR_SLOT_MISSING` | A mandatory slot envelope is absent from the dossier |
| `ERR_SLOT_UNKNOWN` | Effective state is UNKNOWN |
| `ERR_SLOT_ASSERTED` | Effective state is ASSERTED, below the CORROBORATED threshold |
| `ERR_MISSING_PAYLOAD` | Declared state implies a payload but the payload is null |
| `ERR_MISSING_SEAL` | A non-null payload has no cryptographic seal |
| `ERR_SEAL_INTEGRITY_FAILURE` | JCS SHA-256 or HMAC-SHA256 does not match |
| `ERR_AES_GCM_AUTH_FAILURE` | AES-256-GCM authentication or plaintext comparison fails |
| `ERR_ATTESTATION_MISSING` | A non-UNKNOWN slot has no attestation metadata |
| `ERR_ATTESTATION_EXPIRED` | Attestation is expired or has an invalid timestamp |
| `ERR_ATTESTATION_SIGNATURE_INVALID` | Ed25519 signature is malformed or does not verify |
| `ERR_ATTESTATION_PAYLOAD_MISMATCH` | `payload_jcs_sha256` does not match the sealed payload |
| `ERR_ATTESTATION_UNTRUSTED` | Attester key is absent from the relying party's trust store |
| `ERR_ATTESTATION_ACCREDITATION_REQUIRED` | CORROBORATED slot lacks an independent accredited attester |
| `ERR_SEMANTIC_SANCTIONS_NOT_CLEAR` | Supplier sanctions status is not clear |
| `ERR_SEMANTIC_FORCED_LABOUR_SCREENING` | EU 2024/3015 screening status is not CLEAR |
| `ERR_SEMANTIC_SUBCONTRACTING_AUTHORIZED` | Subcontracting is authorized or undeclared |
| `ERR_SEMANTIC_CAPACITY_ZERO` | Declared capacity is absent or non-positive |
| `ERR_SEMANTIC_GEOFENCE_DISTANCE` | S04/S07 Haversine distance exceeds 500 m |
| `ERR_SEMANTIC_STUFFING_GEOFENCE` | S04/S10 factory-stuffing distance exceeds 500 m, or stuffing type is invalid |
| `ERR_SEMANTIC_CARRIER_MISMATCH` | SCAC, B/L number, and container prefix are inconsistent |
| `ERR_SEMANTIC_ORIGIN_CRITERION` | `WO` criterion conflicts with imported tier-2/tier-3 inputs |
| `ERR_SEMANTIC_ORIGIN_REGIME` | Proof type and origin regime are inconsistent |
| `ERR_SEMANTIC_AQL_FAIL` | ISO 2859-1 result is not PASS |
| `ERR_SEMANTIC_CRITICAL_DEFECTS` | Critical defects are non-zero |
| `ERR_SEMANTIC_MAJOR_DEFECTS` | Major defects exceed the acceptance number |
| `ERR_SEMANTIC_REACH_NONCOMPLIANT` | REACH Annex XVII compliance is not attested |
| `ERR_SEMANTIC_AZO_DYES` | Azo dye concentration is 30 ppm or higher |
| `ERR_SEMANTIC_FIBER_TOLERANCE` | Cotton percentage deviates by more than 3.0 points |
| `ERR_SEMANTIC_CONTAINER_MISMATCH` | S10 and S11 container numbers differ |
| `ERR_SEMANTIC_BL_NOT_CLEAN` | Bill of lading is not clean on board |
| `ERR_SEMANTIC_ORIGIN_MISMATCH` | S04 and S12 origin countries differ |
| `ERR_SEMANTIC_REX_MISMATCH` | S05 and S12 REX identifiers differ |
| `ERR_SEMANTIC_CIF_ARITHMETIC` | FOB + freight + insurance does not equal CIF within EUR 0.01 |
| `ERR_SEMANTIC_TARIC_FORMAT` | TARIC code is not exactly 10 digits |

---

## 3. Cryptographic Protocol

### 3.1 RFC 8785 JSON Canonicalization

For a payload `p`, the canonical representation `JCS(p)` satisfies:

1. Object keys are sorted lexicographically by UTF-16 code units.
2. There is no insignificant whitespace between tokens.
3. Strings use ECMAScript JSON escaping, with control characters escaped and non-ASCII characters preserved.
4. Numbers use the ECMAScript `Number.prototype.toString()` serialization.
5. `NaN`, `Infinity`, `undefined`, bigint, functions, symbols, non-plain objects, and cyclic graphs are rejected.
6. Arrays preserve their order.

The canonical payload hash is:

```text
H_JCS = SHA256(UTF8(JCS(p)))
```

### 3.2 RFC 5869 HKDF-SHA256 per-slot key isolation

The input keying material is the 32-byte tenant master secret:

```text
IKM = master_secret (32 bytes)
Salt = dossier_hkdf_salt (16 bytes)
Info = "OOES-18|v1|" || tenant_id || "|" || dossier_id || "|" || slot_id
```

The 32-byte slot key is:

```text
K_slot = HKDF-SHA256(IKM, Salt, Info, L = 32)
```

Changing any of `tenant_id`, `dossier_id`, or `slot_id` by one character yields an uncorrelated key. The protocol therefore gives cryptographic domain separation between tenants, dossiers, and slots even when the same master secret is used across a tenant's portfolio.

### 3.3 Slot digest and authenticated encryption

The deterministic slot authentication digest is:

```text
D_slot = HMAC-SHA256(K_slot, UTF8(JCS(p)))
```

Payload encryption at rest uses AES-256-GCM:

```text
AAD = UTF8(dossier_id || "|" || slot_id || "|" || state)
(C, T) = AES-256-GCM(K_slot, IV, AAD, UTF8(JCS(p)))
```

where `IV` is 96 bits and `T` is the 128-bit authentication tag. The seal record stores `hkdf_salt`, `jcs_sha256`, `hmac_sha256`, `aes_gcm_iv`, `aes_gcm_ciphertext`, `aes_gcm_tag`, and `sealed_at`.

### 3.4 Ed25519 attestation signatures and the trust store

The tenant HMAC in Section 3.3 is a tenant-side integrity control. It is not independent evidence, because any holder of the tenant master secret can recompute it. Attestation authenticity is therefore carried by a separate Ed25519 signature.

Each `AttestationMetadata` record contains:

```text
signature_algorithm       = "Ed25519"
attester_public_key_hex   = 32-byte Ed25519 public key
payload_jcs_sha256        = H_JCS of the attested payload
signature_hex             = 64-byte Ed25519 signature
```

The signed message is the RFC 8785 canonicalization of:

```text
M = JCS({
  slot_id,
  payload_jcs_sha256,
  attester_type,
  authority_name,
  accreditation_id,
  attested_at,
  expires_at,
  signature_algorithm,
  attester_public_key_hex
})
```

The verifier checks:

```text
Ed25519Verify(attester_public_key, UTF8(M), signature) = true
```

and, for a `CORROBORATED` slot, checks that the public key is present in the relying party's trust store for the stated `authority_name`, `accreditation_id`, and slot scope, and that the trust entry is valid at `t_ref`. A valid signature from a key that is not trusted produces `ERR_ATTESTATION_UNTRUSTED`; a payload whose hash does not match `payload_jcs_sha256` produces `ERR_ATTESTATION_PAYLOAD_MISMATCH`.

This gives a relying party a verification path that does not require the tenant master secret:

1. Recompute `H_JCS` from the dossier payload.
2. Compare it to `payload_jcs_sha256`.
3. Verify the Ed25519 signature with the attester's trusted public key.

The tenant HMAC seal remains useful for tenant-side tamper evidence and for AES-GCM key derivation. It is not presented as independent proof. The `L5.S18_AUDIT_SIGNATURE` slot can carry a reviewer's Ed25519 signature over the dossier root for a whole-dossier audit; the base vector leaves it `UNKNOWN` by design.

### 3.5 Dossier state root at L5.S18

Let `D_slot,i` be the authenticated digest of slot `S_i`, or the empty string if the slot is unsealed. The state root is computed over the ordered first seventeen slots:

```text
root = SHA256(UTF8(
    (slot_id_1 || ":" || state_1 || ":" || D_slot,1 || "\n") ||
    (slot_id_2 || ":" || state_2 || ":" || D_slot,2 || "\n") ||
    ...
    (slot_id_17 || ":" || state_17 || ":" || D_slot,17 || "\n")
))
```

The concatenation is direct; the newline is the only separator between records. The slot digest map hash is the SHA-256 of `JCS` over the mapping `slot_id -> D_slot` for `S01..S17`.

`L5.S18_AUDIT_SIGNATURE` carries the state root once a reviewer signs the dossier. In the default test vector, `S18` is `UNKNOWN`, so the root is computed but not yet countersigned.

### 3.6 Salted blind-index duplicate-pledge protocol

#### Normalization

For a shipment, define:

```text
N = Upper(Trim(BL_Number))
    || "|" || Compact(Container_Number)
    || "|" || Compact(Supplier_Tax_ID)
    || "|" || ISO8601_Date(Invoice_Date)
```

where `Compact(x)` removes all whitespace and hyphens and uppercases the result. The common formatting mutation `MSCU-582910-4` versus `MSCU5829104`, or `BD-BIN-004918273-0101` versus `BDBIN0049182730101`, must normalize to the same token.

#### Collision token

```text
blind_index = HMAC-SHA256(Network_Registry_Salt, UTF8(N))
```

The network registry salt is a 32-byte value shared by participating lenders. It is not a tenant secret and is not the tenant master secret.

#### Threat model

| Adversary capability | Protocol property |
| :--- | :--- |
| A lender sees only its own tenant secret | Cannot derive another tenant's slot keys or plaintext values |
| Two lenders share the network salt | Detect the same normalized shipment tuple without sharing B/L, container, tax ID, or invoice date in plaintext |
| An adversary mutates formatting (`-`, spaces, case) | Normalization strips separators and uppercases, so the collision token is unchanged |
| An adversary attempts a preimage or second preimage | HMAC-SHA256 with a 256-bit salt; no feasible attack |
| An adversary enumerates candidate tuples offline | The tuple is structured, not uniformly random: B/L numbers follow carrier patterns and container/tax identifiers are partly predictable. The salt MUST be access-controlled, queries MUST be rate-limited, and salts SHOULD be rotated. The blind index is a duplicate-detection signal, not a privacy guarantee against an adversary who already holds the salt |
| A lender observes a collision | Learns that two submissions share a tuple, not the amounts, currencies, or commercial terms |
| Two different shipments collide | Cryptographically negligible for a 256-bit tag |

A blind-index collision is a **signal**, not a fraud verdict. It establishes that two lending submissions share the same normalized shipment identity. Human review and documentary reconciliation remain necessary.

#### Cross-bank example

```text
Bank A input:  ("MSCU260984112", " mscu-582910-4 ", "bd-bin-004918273-0101", "2026-10-12")
Bank B input:  (" mscu260984112 ", "MSCU5829104", "BDBIN0049182730101", "2026-10-12")
Normalized:    MSCU260984112|MSCU5829104|BDBIN0049182730101|2026-10-12
Blind index:   3eea022417dbb6dcbefca0e1e7c3c4f0c1fe764c0b017a957324e2e54f1b4125
```

Both banks compute the same 256-bit token without exchanging tenant keys or commercial plaintext.

### 3.7 Security properties of the sealing layer

- **Tenant isolation.** Different `tenant_id` values produce different slot keys.
- **Dossier isolation.** Different `dossier_id` values produce different slot keys even for the same slot.
- **Slot isolation.** Different slots produce different keys, so a digest cannot be transplanted between slots.
- **Tamper evidence.** Any payload mutation changes `JCS(p)`, `H_JCS`, and `D_slot`, and invalidates the GCM tag.
- **Non-forgeability without the master secret.** An attacker with the dossier bytes but no `master_secret` cannot recompute `K_slot` and therefore cannot forge a valid HMAC or GCM tag.
- **Independent attestation.** A relying party can verify the Ed25519 attestation over `payload_jcs_sha256` with the attester's trusted public key, without the tenant master secret. A tenant cannot mint a trusted attestation without the attester's private key.
- **Deterministic replay.** Given the same dossier, trust store, and master secret, every digest and verdict is reproducible bit-for-bit.

The sealing layer does not protect against a compromised tenant master secret, a malicious accredited oracle, a stolen attester private key, or a coerced reviewer who signs a false attestation. Those are institutional and key-management threats, addressed by HSM custody, oracle accreditation, key revocation, and audit, not by cryptography alone.

---

## 4. Institutional Output Mappings

### 4.1 View A: `pre_wire_gate`

Audience: corporate ERP, treasury, and payment orchestration.

The view returns:

```json
{
  "gate_id": "GATE_01_DEPOSIT_PRE_WIRE",
  "verdict": "READY | HARD_STOP",
  "advance_amount_eur": 43200.00,
  "currency": "EUR",
  "mandatory_slots": ["L1.S01_PURCHASE_ORDER", "..."],
  "uncorroborated_slots": ["..."],
  "halt_reasons": [{"code": "ERR_SLOT_ASSERTED", "slot_id": "...", "detail": "..."}],
  "generated_at": "2026-10-20T12:00:00Z"
}
```

The ERP MUST NOT release the Day-0 wire when the verdict is `HARD_STOP`. The advance amount is 30% of the corroborated purchase-order total, reported for treasury reconciliation only; it is not an authorization.

### 4.2 View B: `lc_mt700_check` (UCP 600 and ISBP 821)

Audience: trade-finance bank, document examiner, credit insurer.

| Reference | OOES-18 check | Source slots |
| :--- | :--- | :--- |
| UCP 600 Art. 14(d) | Data in a document must not conflict with data in any other stipulated document | `S04`, `S05`, `S10`, `S11`, `S12` |
| UCP 600 Art. 18 / ISBP 821 Para. C1 | Commercial invoice issued by the beneficiary, in the credit currency, reconcilable to the PO | `S01`, `S14` |
| UCP 600 Art. 20 / ISBP 821 Para. E1 | Bill of lading shows shipment on board a named vessel and is clean | `S10`, `S11` |
| UCP 600 Art. 27 | Transport document bears no defective-condition clause | `S11` |
| UCP 600 Art. 30 | Quantity tolerance of 5% when quantity is not stipulated in packing units | `S01`, `S16` |
| ISBP 821 Para. L1 | Certificate of origin is consistent with invoice, transport document, origin, and REX | `S04`, `S05`, `S12` |

The view status is `CLEAN`, `DISCREPANT`, or `INCOMPLETE`. A `DISCREPANT` check is a semantic contradiction; an `INCOMPLETE` check has an unevaluated source slot. Both block the relevant gate.

CIF customs valuation is governed by UCC Articles 70 and 71, not by ISBP 821 Section K. Section K addresses insurance documents. The H1 view therefore carries the customs-value mapping, and this view does not claim an ISBP K1 freight/insurance test.

### 4.3 View C: `delta_ie_h1_pack` (French DGDDI DELTA IE H1)

Audience: French customs broker, RDE, importer of record.

| DELTA IE H1 data element | OOES-18 source | Notes |
| :--- | :--- | :--- |
| `DE 11 01` Declaration type `H1` | `L5.S15` | Release for free circulation |
| `DE 12 03` Supporting documents | `L1.S01`, `L3.S09`, `L4.S11`, `L4.S12`, `L5.S14` | Commercial invoice `N380`, B/L `N705`, origin `U164`/`N865`, ISO 17025 lab certificate, forced-labour attestation |
| `DE 13 01` Exporter identity and address | `L2.S04` | Legal name, tax registration, country |
| `DE 13 04` Importer EORI | `L1.S01` | `buyer_eori` |
| `DE 14 03` Customs value and Incoterms breakdown | `L5.S14` | UCC Art. 70/71; FOB + freight + insurance = CIF |
| `DE 16 08 / 16 09` Non-preferential and preferential origin | `L4.S12` | Country, criterion, REX |
| `DE 18 09` Commodity code | `L5.S15` | 10-digit TARIC |
| `DE 19 01 / 19 07` Container and seal | `L4.S10`, `L4.S11` | Container number and ISO 17712 seal |

The pack is `READY` only when every data element is `COMPLETE`. A `PENDING` element exists but is not corroborated. A `MISSING` element has no payload. The same `S14` valuation arithmetic that satisfies `GATE_02` populates `DE 14 03`; the same `S15` TARIC code populates `DE 18 09`; the same `S10` seal populates `DE 19 01 / 19 07`.

### 4.4 The Oracle Boundary Theorem

**Theorem (Oracle Boundary).** Let `TenantSeal(s)` denote a valid HMAC-SHA256 and AES-256-GCM seal on slot `s` under `K_slot`. Let `Attest(s)` denote a valid Ed25519 attestation over the payload hash under a trusted attester key. Let `Physical(s)` denote the proposition that the physical event described by `s` occurred as stated. Then:

```text
TenantSeal(s) does not imply Physical(s)
Attest(s) does not imply Physical(s)
```

**Proof sketch.** `TenantSeal(s)` is a function of the payload bytes, the tenant master secret, the dossier salt, the slot identifier, and the reference state. It is computed entirely inside the tenant's key domain. It is invariant under the truth or falsity of `Physical(s)`. `Attest(s)` proves that the holder of a trusted attester key signed the payload hash; it does not prove that the attester observed the event correctly, that the sample came from the declared batch, or that the attester's accreditation is unrevoked. A tenant can seal a false payload; a trusted oracle can attest a false observation; a compromised device can report false GPS. Therefore seal validity proves tenant-side integrity, and attestation validity proves attester authenticity, but neither proves physical truth.

Physical ground truth enters the model only through the `ASSERTED -> CORROBORATED` transition, and that transition requires:

1. An independent attester whose `attester_type` is not `PARTY_SELF_DECLARATION`.
2. A verified `accreditation_id` (ISO/IEC 17020, ISO/IEC 17025, sovereign registry, carrier eBL registry).
3. A valid Ed25519 signature over the payload hash.
4. A public key present in the relying party's trust store for that authority, accreditation ID, and slot scope, valid at `t_ref`.

The accredited attester is the oracle. The cryptographic layer secures the oracle's statement after capture and lets a relying party verify it without the tenant secret. The accreditation and trust-store layers establish the oracle's competence and independence. All are necessary. None is sufficient alone. This is the precise boundary between cryptographic integrity, attestation authenticity, and institutional truth.

### 4.5 Limitations

- **Accreditation freshness.** OOES-18 verifies that an accreditation identifier is present, the attestation is unexpired, and the attester key is in the trust store. It does not query the accreditation body in real time. Implementations SHOULD maintain a revocation feed and a trust-store update process.
- **Attester key compromise.** A stolen attester private key can sign a false payload hash. The trust store limits the blast radius but cannot detect a compromised key without revocation. Attesters SHOULD use HSM-backed keys and publish revocation status.
- **Oracle collusion.** Two colluding parties, one self-declared and one accredited, can defeat the epistemic threshold. Accreditation independence is an institutional control, not a cryptographic one.
- **Clock trust.** Timestamps are only as trustworthy as their source. Hardware TPM quotes and sovereign timestamps reduce, but do not eliminate, clock manipulation risk.
- **Carrier-prefix heuristic.** The SCAC/B-L/container prefix check is syntactic, not a carrier-ownership determination. Leased containers, vessel-sharing, and co-loading can legitimately use different prefixes. Implementations MAY replace the prefix rule with a carrier-registry lookup; the rule exists to catch obvious document-assembly errors such as a Maersk SCAC on an MSC container.
- **Blind-index enumeration.** The normalized tuple is structured, and B/L numbers follow carrier patterns. An adversary holding the shared salt can test candidate tuples. The salt MUST be access-controlled and queries rate-limited; salt rotation SHOULD be supported. A collision is a review signal, not proof of fraud.
- **Schema evolution.** Version 1.1.0 fixes the 18 slot identifiers. Additive fields require a minor version; changing a mandatory field or gate predicate requires a major version.
- **No physical inspection by the kernel.** The verifier reads bytes. It does not see the factory floor, the container, or the laboratory bench.

---

## 5. Reference Implementation and Test Vector

The reference verifier is implemented in TypeScript and uses only Node.js built-in modules: `node:crypto`, `node:fs`, `node:path`, `node:test`, and `node:assert/strict`. It exports `canonicalizeJCS`, `computeJcsSha256`, `deriveSlotKey`, `computeSlotDigest`, `encryptSlotPayload`, `computeDossierMerkleRoot`, `computeBlindIndex`, `verifyDossierSeals`, and `evaluateReleaseGates`.

The test vector `CASCADE-2026-9F4A2C` represents a Dhaka (`BDCGP`) to Le Havre (`FRLEH`) shipment:

- Commodity: men's 100% heavy cotton twill workwear jackets, 290 GSM
- TARIC: `6203321000`
- Quantity: 12,000 units at EUR 12.00
- FOB: EUR 144,000.00
- Freight: EUR 4,200.00
- Insurance: EUR 300.00
- CIF: EUR 148,500.00
- B/L: `MSCU260984112` (SCAC `MSCU`, vessel `MSC ISABELLA`, IMO `9839272`)
- Container: `MSCU5829104`
- State distribution: 8 CORROBORATED, 4 ASSERTED, 6 UNKNOWN

Pinned cryptographic fixtures:

```text
master_secret = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
hkdf_salt     = a1b2c3d4e5f60718293a4b5c6d7e8f90
registry_salt = f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f
```

The default vector produces:

```text
GATE_01_DEPOSIT_PRE_WIRE             = HARD_STOP
  uncorroborated: L2.S05_REGISTRY_STANDING (ASSERTED),
                  L2.S06_CAPACITY_ATTESTATION (ASSERTED)

GATE_02_BALANCE_AND_PRE_CLEARANCE    = HARD_STOP
  uncorroborated: L2.S05_REGISTRY_STANDING (ASSERTED),
                  L4.S11_BILL_OF_LADING (ASSERTED),
                  L4.S12_CERTIFICATE_OF_ORIGIN (ASSERTED),
                  L5.S14_LANDED_VALUATION (UNKNOWN),
                  L5.S15_DUTY_CALCULATION (UNKNOWN),
                  L5.S16_PSI_REPORT (UNKNOWN)
```

The automated suite demonstrates that full corroboration of `S05`, `S06`, `S11`, `S12`, `S14`, `S15`, and `S16` transitions both gates to `READY`, and that a container mismatch, factory/media or factory/stuffing geofence violation, `WO` origin with imported inputs, carrier/SCAC mismatch, or CIF arithmetic error returns both gates to `HARD_STOP` even when every seal is valid. A single-byte mutation of `L3.S09_LAB_CERTIFICATE.measured_cotton_pct` demotes the slot to `UNKNOWN` and halts `GATE_02`. A valid Ed25519 signature from a key outside the trust store is also rejected.

---

## 6. Conformance

An implementation conforms to OOES-18 v1.1.0 if and only if it:

1. Accepts the schema at `schema/ooes-18.schema.json`.
2. Reproduces every digest, authentication tag, Ed25519 signature, state root, and blind index in `vectors/CASCADE-2026-9F4A2C.dossier.json` and `trust/attesters.json` from the pinned fixtures.
3. Returns `HARD_STOP` for both gates on the default vector with the exact uncorroborated slot sets in Section 5.
4. Passes the tamper demonstration: mutating `L3.S09` causes `ERR_SEAL_INTEGRITY_FAILURE` and `ERR_ATTESTATION_PAYLOAD_MISMATCH`, demotion to `UNKNOWN`, and a `GATE_02` hard stop.
5. Rejects a fully corroborated dossier with a container mismatch, factory/media or factory/stuffing geofence violation, `WO` origin with imported inputs, carrier/SCAC mismatch, or CIF arithmetic error.
6. Rejects a valid Ed25519 signature whose key is absent from the trust store, and a mutated attestation signature.
7. Computes identical blind indices for the two formatted bank inputs in Section 3.6.

Normative keywords `MUST`, `MUST NOT`, `SHALL`, `SHOULD`, and `MAY` are used as defined in RFC 2119.

---

## 7. Conclusion

The 75-day epistemic gap is not a document-processing problem. It is an evidence-state problem. OCR and LLMs can read a PDF faster than a human, but reading faster does not create independent corroboration. Consortium ledgers can share a record, but sharing a record does not establish that the factory, container, or laboratory observation was true.

OOES-18 makes the evidence state explicit, bounds it to a three-valued lattice, seals every slot with per-tenant derived keys, verifies attester authenticity with Ed25519 and a relying-party trust store, and forces a deterministic two-gate decision before capital moves and before the H1 declaration is filed. The protocol is narrow enough to implement with Node's standard library and strict enough to distinguish a self-declared PDF from an accredited, independently verifiable attestation. That distinction is the institutional contribution.

---

## References

1. Regulation (EU) 2024/3015 of the European Parliament and of the Council on prohibiting products made with forced labour on the Union market, OJ L, 13 December 2024.
2. Regulation (EU) 2024/1781 establishing a framework for the setting of ecodesign requirements for sustainable products, OJ L, 28 June 2024.
3. Union Customs Code, Regulation (EU) No 952/2013, Annex B data requirements.
4. French Directorate General of Customs and Excise (DGDDI), DELTA IE Volet Import (H1), notice of 30 September 2025, https://www.douane.gouv.fr/sites/default/files/2025-10/01/Notice_DELTA_IE_30_septembre_2025.pdf.
5. ICC, Uniform Customs and Practice for Documentary Credits, UCP 600 (2007), Articles 14(d), 18, 20, 27, and 30.
6. ICC, International Standard Banking Practice for the Examination of Documents under UCP 600, ISBP 821 (2023).
7. A. Rundgren, B. Jordan, S. Erdtman, RFC 8785: JSON Canonicalization Scheme (JCS), IETF, June 2020.
8. H. Krawczyk, P. Eronen, RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF), IETF, May 2010.
9. NIST, FIPS 197: Advanced Encryption Standard (AES), 2001; NIST SP 800-38D: Galois/Counter Mode (GCM), 2007; S. Josefsson and I. Liusvaara, RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA), IETF, January 2017.
10. ISO 2859-1:1999, Sampling procedures for inspection by attributes.
11. ISO/IEC 17020:2012, Conformity assessment - Requirements for the operation of various types of bodies performing inspection.
12. ISO/IEC 17025:2017, General requirements for the competence of testing and calibration laboratories.
13. ISO 17712:2013, Freight containers - Mechanical seals.
14. M. Anwaruzzaman, First-Order Manufacturing Failure in Small-Firm International Sourcing: A Practice-Derived Cascade Model from 412 Cases (DS-PR412, 2011–2024), SSRN #6661398, DOI 10.2139/ssrn.6661398, 2026.
