import crypto from "node:crypto";

/**
 * OOES-18 v1.1.0 reference verifier.
 *
 * A model reads. A compiled kernel decides.
 *
 * Everything in this module is pure and deterministic. No fuzzy matching,
 * no confidence scores, and no probabilistic inference are permitted in
 * the release evaluation path.
 */

export const STANDARD_ID = "OOES-18" as const;
export const STANDARD_VERSION = "1.1.0" as const;

export const SLOT_IDS = [
  "L1.S01_PURCHASE_ORDER",
  "L1.S02_TECH_PACK",
  "L1.S03_GOLDEN_SAMPLE",
  "L2.S04_SUPPLIER_KYB",
  "L2.S05_REGISTRY_STANDING",
  "L2.S06_CAPACITY_ATTESTATION",
  "L3.S07_PRODUCTION_PHOTOS",
  "L3.S08_INLINE_AQL",
  "L3.S09_LAB_CERTIFICATE",
  "L4.S10_BOLT_SEAL",
  "L4.S11_BILL_OF_LADING",
  "L4.S12_CERTIFICATE_OF_ORIGIN",
  "L4.S13_SETTLEMENT_INSTRUMENT",
  "L5.S14_LANDED_VALUATION",
  "L5.S15_DUTY_CALCULATION",
  "L5.S16_PSI_REPORT",
  "L5.S17_GPS_TELEMETRY",
  "L5.S18_AUDIT_SIGNATURE"
] as const;

export type SlotId = (typeof SLOT_IDS)[number];

export type Layer = "L1" | "L2" | "L3" | "L4" | "L5";

export const SLOT_LAYER: Record<SlotId, Layer> = {
  "L1.S01_PURCHASE_ORDER": "L1",
  "L1.S02_TECH_PACK": "L1",
  "L1.S03_GOLDEN_SAMPLE": "L1",
  "L2.S04_SUPPLIER_KYB": "L2",
  "L2.S05_REGISTRY_STANDING": "L2",
  "L2.S06_CAPACITY_ATTESTATION": "L2",
  "L3.S07_PRODUCTION_PHOTOS": "L3",
  "L3.S08_INLINE_AQL": "L3",
  "L3.S09_LAB_CERTIFICATE": "L3",
  "L4.S10_BOLT_SEAL": "L4",
  "L4.S11_BILL_OF_LADING": "L4",
  "L4.S12_CERTIFICATE_OF_ORIGIN": "L4",
  "L4.S13_SETTLEMENT_INSTRUMENT": "L4",
  "L5.S14_LANDED_VALUATION": "L5",
  "L5.S15_DUTY_CALCULATION": "L5",
  "L5.S16_PSI_REPORT": "L5",
  "L5.S17_GPS_TELEMETRY": "L5",
  "L5.S18_AUDIT_SIGNATURE": "L5"
};

export type EpistemicState = "UNKNOWN" | "ASSERTED" | "CORROBORATED";

export interface CryptographicSeal {
  hkdf_salt: string;
  jcs_sha256: string;
  hmac_sha256: string;
  aes_gcm_iv: string;
  aes_gcm_ciphertext: string;
  aes_gcm_tag: string;
  sealed_at: string;
}

export type AttesterType =
  | "PARTY_SELF_DECLARATION"
  | "ACCREDITED_THIRD_PARTY"
  | "SOVEREIGN_AUTHORITY"
  | "CARRIER_REGISTRY"
  | "BANK";

export interface AttestationMetadata {
  attester_type: AttesterType;
  authority_name: string;
  accreditation_id: string | null;
  attested_at: string;
  expires_at: string;
  signature_algorithm: "Ed25519";
  attester_public_key_hex: string;
  payload_jcs_sha256: string;
  signature_hex: string;
}

export interface AttesterTrustEntry {
  authority_name: string;
  accreditation_id: string;
  public_key_hex: string;
  valid_from: string;
  valid_until: string;
  scopes: string[];
}

export interface AttesterTrustStore {
  version: string;
  test_only?: boolean;
  note?: string;
  attesters: AttesterTrustEntry[];
}

export interface SlotEnvelope {
  slot_id: string;
  layer: Layer;
  state: EpistemicState;
  payload: Record<string, unknown> | null;
  seal: CryptographicSeal | null;
  attestation: AttestationMetadata | null;
  fault_codes: string[];
}

export interface BlindIndexRecord {
  normalized_tuple: string;
  blind_index_hex: string;
  registry_salt_id: string;
}

export interface OOES18Dossier {
  standard: typeof STANDARD_ID;
  version: string;
  dossier_id: string;
  tenant_id: string;
  created_at: string;
  reference_time: string;
  hkdf_salt_hex: string;
  slots: Record<string, SlotEnvelope>;
  blind_index: BlindIndexRecord;
  dossier_state_root: string;
  slot_digests_map_hash: string;
  institutional_views?: InstitutionalViews;
}

export interface SlotSealReport {
  slot_id: string;
  layer: string;
  declared_state: EpistemicState;
  effective_state: EpistemicState;
  jcs_sha256_match: boolean;
  hmac_sha256_match: boolean;
  aes_gcm_authenticated: boolean;
  attestation_valid: boolean;
  attestation_trusted: boolean;
  fault_codes: string[];
}

export interface SealVerificationReport {
  dossier_id: string;
  reference_time: string;
  ok: boolean;
  all_seals_valid: boolean;
  slots: SlotSealReport[];
  errors: string[];
}

export interface HaltReason {
  code: string;
  slot_id: string | null;
  detail: string;
}

export type SemanticStatus = "PASS" | "FAIL" | "NOT_EVALUATED";

export interface SemanticCheck {
  rule_id: string;
  source_slots: string[];
  status: SemanticStatus;
  detail: string;
}

export interface GateResult {
  gate_id: string;
  verdict: "READY" | "HARD_STOP";
  mandatory_slots: string[];
  uncorroborated_slots: string[];
  slot_states: Record<string, EpistemicState>;
  halt_reasons: HaltReason[];
  semantic_checks: SemanticCheck[];
  semantics_ok: boolean;
}

export interface PreWireGateView {
  gate_id: string;
  verdict: "READY" | "HARD_STOP";
  advance_amount_eur: number;
  currency: string;
  mandatory_slots: string[];
  uncorroborated_slots: string[];
  halt_reasons: HaltReason[];
  generated_at: string;
}

export interface LcCheck {
  reference: string;
  requirement: string;
  source_slots: string[];
  status: SemanticStatus;
  detail: string;
}

export interface LcMt700CheckView {
  profile: "UCP_600_ISBP_821";
  overall: "CLEAN" | "DISCREPANT" | "INCOMPLETE";
  checks: LcCheck[];
  generated_at: string;
}

export interface DeltaDataElement {
  de: string;
  name: string;
  source_slots: string[];
  status: "COMPLETE" | "PENDING" | "MISSING";
  values: Record<string, unknown>;
}

export interface DeltaIeH1PackView {
  declaration_type: "H1";
  entry_process: "DELTA_IE_VOLET_IMPORT_H1";
  overall: "READY" | "INCOMPLETE";
  data_elements: DeltaDataElement[];
  generated_at: string;
}

export interface InstitutionalViews {
  pre_wire_gate: PreWireGateView;
  lc_mt700_check: LcMt700CheckView;
  delta_ie_h1_pack: DeltaIeH1PackView;
}

export interface GateEvaluationReport {
  dossier_id: string;
  tenant_id: string;
  reference_time: string;
  seal_verification: SealVerificationReport;
  gates: {
    GATE_01_DEPOSIT_PRE_WIRE: GateResult;
    GATE_02_BALANCE_AND_PRE_CLEARANCE: GateResult;
  };
  institutional_views: InstitutionalViews;
  blind_index: BlindIndexRecord | null;
}

const HEX_32_BYTES = 64;
const HEX_16_BYTES = 32;
const HEX_12_BYTES = 24;
const UTF8 = "utf8" as const;

function sha256Hex(data: Buffer | string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function assertHex(value: string, expectedBytes: number, label: string): Buffer {
  if (typeof value !== "string" || value.length !== expectedBytes * 2 || !/^[0-9a-fA-F]+$/.test(value)) {
    throw new TypeError(`${label} must be ${expectedBytes} bytes of hexadecimal data`);
  }
  return Buffer.from(value, "hex");
}

function assertNonEmpty(value: string, label: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
}

/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * Objects are serialized with keys sorted by UTF-16 code units, arrays keep
 * their order, strings use ECMAScript JSON escaping, and numbers use the
 * ECMAScript Number::toString algorithm. NaN, Infinity, undefined, bigint,
 * functions, symbols, and cycles are rejected.
 */
export function canonicalizeJCS(value: unknown): string {
  return serializeJcs(value, new Set<object>());
}

function serializeJcs(value: unknown, seen: Set<object>): string {
  if (value === null) {
    return "null";
  }

  const valueType = typeof value;

  if (valueType === "string") {
    return JSON.stringify(value);
  }

  if (valueType === "number") {
    if (!Number.isFinite(value as number)) {
      throw new TypeError("JCS does not permit NaN or Infinity");
    }
    return JSON.stringify(value);
  }

  if (valueType === "boolean") {
    return value === true ? "true" : "false";
  }

  if (valueType === "object") {
    const objectValue = value as object;
    if (seen.has(objectValue)) {
      throw new TypeError("JCS does not permit cyclic object graphs");
    }
    seen.add(objectValue);

    let serialized: string;
    if (Array.isArray(value)) {
      const parts: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const item = value[index];
        if (item === undefined) {
          throw new TypeError("JCS arrays cannot contain undefined values");
        }
        parts.push(serializeJcs(item, seen));
      }
      serialized = `[${parts.join(",")}]`;
    } else {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError("JCS only accepts plain JSON objects");
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      const parts: string[] = [];
      for (const key of keys) {
        const item = record[key];
        if (item === undefined) {
          throw new TypeError("JCS objects cannot contain undefined values");
        }
        parts.push(`${JSON.stringify(key)}:${serializeJcs(item, seen)}`);
      }
      serialized = `{${parts.join(",")}}`;
    }

    seen.delete(objectValue);
    return serialized;
  }

  throw new TypeError(`JCS cannot serialize a value of type ${valueType}`);
}

/** Lowercase SHA-256 of the UTF-8 RFC 8785 canonical form. */
export function computeJcsSha256(payload: unknown): string {
  return sha256Hex(Buffer.from(canonicalizeJCS(payload), UTF8));
}

/**
 * RFC 5869 HKDF-SHA256 per-slot key derivation.
 *
 * info = "OOES-18|v1|" || tenant_id || "|" || dossier_id || "|" || slot_id
 */
export function deriveSlotKey(
  masterSecretHex: string,
  hkdfSaltHex: string,
  tenantId: string,
  dossierId: string,
  slotId: string
): Buffer {
  const ikm = assertHex(masterSecretHex, 32, "master_secret_hex");
  const salt = assertHex(hkdfSaltHex, 16, "hkdf_salt_hex");
  assertNonEmpty(tenantId, "tenant_id");
  assertNonEmpty(dossierId, "dossier_id");
  assertNonEmpty(slotId, "slot_id");

  const info = Buffer.from(`OOES-18|v1|${tenantId}|${dossierId}|${slotId}`, UTF8);
  const okm = crypto.hkdfSync("sha256", ikm, salt, info, 32);
  return Buffer.from(okm);
}

/** HMAC-SHA256(slotKey, UTF8(JCS(payload))). */
export function computeSlotDigest(slotKey: Buffer, payload: unknown): string {
  if (!Buffer.isBuffer(slotKey) || slotKey.length !== 32) {
    throw new TypeError("slotKey must be a 32-byte Buffer");
  }
  return crypto
    .createHmac("sha256", slotKey)
    .update(Buffer.from(canonicalizeJCS(payload), UTF8))
    .digest("hex");
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Canonical message signed by an attester.
 *
 * The signature binds the attester identity, accreditation, validity window,
 * public key, and the JCS SHA-256 of the attested payload. A relying party can
 * therefore verify that the attester signed this exact payload hash without
 * possessing the tenant's HMAC master secret.
 */
export function attestationMessage(
  slotId: string,
  payloadJcsSha256: string,
  metadata: AttestationMetadata
): string {
  return canonicalizeJCS({
    slot_id: slotId,
    payload_jcs_sha256: payloadJcsSha256,
    attester_type: metadata.attester_type,
    authority_name: metadata.authority_name,
    accreditation_id: metadata.accreditation_id,
    attested_at: metadata.attested_at,
    expires_at: metadata.expires_at,
    signature_algorithm: metadata.signature_algorithm,
    attester_public_key_hex: metadata.attester_public_key_hex
  });
}

/** Verify an Ed25519 attestation signature over the canonical message. */
export function verifyAttestationSignature(
  slotId: string,
  payloadJcsSha256: string,
  metadata: AttestationMetadata
): boolean {
  try {
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([
        ED25519_SPKI_PREFIX,
        assertHex(metadata.attester_public_key_hex, 32, "attester_public_key_hex")
      ]),
      format: "der",
      type: "spki"
    });
    const signature = assertHex(metadata.signature_hex, 64, "signature_hex");
    const message = Buffer.from(
      attestationMessage(slotId, payloadJcsSha256, metadata),
      UTF8
    );
    return crypto.verify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}

/** True when the attester key is in the relying party's trust store. */
export function isTrustedAttester(
  trustStore: AttesterTrustStore | undefined,
  metadata: AttestationMetadata,
  slotId: string,
  referenceTime: string
): boolean {
  if (!trustStore || !Array.isArray(trustStore.attesters)) {
    return false;
  }
  const reference = Date.parse(referenceTime);
  if (!Number.isFinite(reference)) {
    return false;
  }
  return trustStore.attesters.some((entry) => {
    if (
      typeof entry.authority_name !== "string" ||
      typeof entry.accreditation_id !== "string" ||
      typeof entry.public_key_hex !== "string" ||
      !Array.isArray(entry.scopes)
    ) {
      return false;
    }
    if (entry.authority_name !== metadata.authority_name) {
      return false;
    }
    if (entry.accreditation_id !== metadata.accreditation_id) {
      return false;
    }
    if (entry.public_key_hex.toLowerCase() !== metadata.attester_public_key_hex.toLowerCase()) {
      return false;
    }
    const validFrom = Date.parse(entry.valid_from);
    const validUntil = Date.parse(entry.valid_until);
    if (
      !Number.isFinite(validFrom) ||
      !Number.isFinite(validUntil) ||
      reference < validFrom ||
      reference > validUntil
    ) {
      return false;
    }
    return (
      entry.scopes.length === 0 ||
      entry.scopes.includes("*") ||
      entry.scopes.includes(slotId)
    );
  });
}

/**
 * AES-256-GCM payload encryption at rest.
 *
 * AAD = UTF8(dossier_id || "|" || slot_id || "|" || state)
 */
export function encryptSlotPayload(
  slotKey: Buffer,
  ivHex: string,
  dossierId: string,
  slotId: string,
  state: string,
  payload: unknown
): { ciphertextHex: string; authTagHex: string } {
  if (!Buffer.isBuffer(slotKey) || slotKey.length !== 32) {
    throw new TypeError("slotKey must be a 32-byte Buffer");
  }
  const iv = assertHex(ivHex, 12, "aes_gcm_iv");
  assertNonEmpty(dossierId, "dossier_id");
  assertNonEmpty(slotId, "slot_id");
  assertNonEmpty(state, "state");

  const cipher = crypto.createCipheriv("aes-256-gcm", slotKey, iv);
  cipher.setAAD(Buffer.from(`${dossierId}|${slotId}|${state}`, UTF8));
  const plaintext = Buffer.from(canonicalizeJCS(payload), UTF8);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertextHex: ciphertext.toString("hex"),
    authTagHex: cipher.getAuthTag().toString("hex")
  };
}

/**
 * L5.S18 dossier state root over S01..S17.
 *
 * root = SHA256(UTF8(concat for i=1..17: slot_id_i + ":" + state_i + ":" +
 *        slot_digest_i + "\n"))
 */
export function computeDossierMerkleRoot(slots: Record<string, SlotEnvelope>): string {
  const lines: string[] = [];
  for (const slotId of SLOT_IDS.slice(0, 17)) {
    const envelope = slots[slotId];
    const state = envelope?.state ?? "UNKNOWN";
    const digest = envelope?.seal?.hmac_sha256 ?? "";
    lines.push(`${slotId}:${state}:${digest}\n`);
  }
  return sha256Hex(Buffer.from(lines.join(""), UTF8));
}

/** SHA-256 of the JCS mapping slot_id -> authenticated slot digest (S01..S17). */
export function computeSlotDigestsMapHash(slots: Record<string, SlotEnvelope>): string {
  const digests: Record<string, string> = {};
  for (const slotId of SLOT_IDS.slice(0, 17)) {
    digests[slotId] = slots[slotId]?.seal?.hmac_sha256 ?? "";
  }
  return computeJcsSha256(digests);
}

function normalizeBl(value: string): string {
  return value.trim().toUpperCase();
}

function normalizeCompact(value: string): string {
  return value.replace(/[\s-]+/g, "").toUpperCase();
}

/**
 * Salted blind-index normalization for cross-lender duplicate-pledge
 * detection. Hyphens and whitespace are stripped from the container and
 * supplier tax identifier so formatting mutations cannot evade collision.
 */
export function computeBlindIndex(
  registrySaltHex: string,
  blNumber: string,
  containerId: string,
  supplierTaxId: string,
  invoiceDate: string
): { normalizedTuple: string; blindIndexHex: string } {
  const salt = assertHex(registrySaltHex, 32, "network_registry_salt");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(invoiceDate)) {
    throw new TypeError("invoiceDate must be an ISO 8601 calendar date (YYYY-MM-DD)");
  }
  const parsed = Date.parse(`${invoiceDate}T00:00:00Z`);
  if (!Number.isFinite(parsed)) {
    throw new TypeError("invoiceDate is not a valid calendar date");
  }

  const normalizedTuple = [
    normalizeBl(blNumber),
    normalizeCompact(containerId),
    normalizeCompact(supplierTaxId),
    invoiceDate
  ].join("|");

  const blindIndexHex = crypto
    .createHmac("sha256", salt)
    .update(Buffer.from(normalizedTuple, UTF8))
    .digest("hex");

  return { normalizedTuple, blindIndexHex };
}

function payloadOf(dossier: OOES18Dossier, slotId: string): Record<string, unknown> | null {
  return dossier.slots[slotId]?.payload ?? null;
}

function numberOf(payload: Record<string, unknown> | null, key: string): number | null {
  if (!payload) {
    return null;
  }
  const value = payload[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringOf(payload: Record<string, unknown> | null, key: string): string | null {
  if (!payload) {
    return null;
  }
  const value = payload[key];
  return typeof value === "string" ? value : null;
}

function booleanOf(payload: Record<string, unknown> | null, key: string): boolean | null {
  if (!payload) {
    return null;
  }
  const value = payload[key];
  return typeof value === "boolean" ? value : null;
}

/**
 * Full cryptographic verification of all 18 slots. Tampered or expired
 * slots are demoted to UNKNOWN in the report; the input is never mutated.
 */
export function verifyDossierSeals(
  dossier: OOES18Dossier,
  masterSecretHex: string,
  referenceTime: string = dossier.reference_time,
  trustStore?: AttesterTrustStore
): SealVerificationReport {
  const parsedReference = Date.parse(referenceTime);
  if (!Number.isFinite(parsedReference)) {
    throw new TypeError("reference_time must be a valid ISO 8601 timestamp");
  }

  const reports: SlotSealReport[] = [];
  const errors: string[] = [];

  for (const slotId of SLOT_IDS) {
    const envelope = dossier.slots[slotId];
    const layer = SLOT_LAYER[slotId];

    if (!envelope) {
      reports.push({
        slot_id: slotId,
        layer,
        declared_state: "UNKNOWN",
        effective_state: "UNKNOWN",
        jcs_sha256_match: false,
        hmac_sha256_match: false,
        aes_gcm_authenticated: false,
        attestation_valid: false,
        attestation_trusted: false,
        fault_codes: ["ERR_SLOT_MISSING"]
      });
      errors.push(`${slotId}: mandatory slot envelope is missing`);
      continue;
    }

    const declaredState: EpistemicState = envelope.state;
    let effectiveState: EpistemicState = envelope.state;
    const faults: string[] = Array.isArray(envelope.fault_codes) ? [...envelope.fault_codes] : [];

    let jcsMatch = false;
    let hmacMatch = false;
    let aesAuthenticated = false;
    let payloadJcsSha = "";

    const demote = (code: string, detail?: string): void => {
      effectiveState = "UNKNOWN";
      if (!faults.includes(code)) {
        faults.push(code);
      }
      if (detail) {
        errors.push(`${slotId}: ${detail}`);
      }
    };

    if (envelope.payload === null) {
      if (declaredState !== "UNKNOWN") {
        demote("ERR_MISSING_PAYLOAD", `declared ${declaredState} but payload is null`);
      }
      reports.push({
        slot_id: slotId,
        layer,
        declared_state: declaredState,
        effective_state: effectiveState,
        jcs_sha256_match: false,
        hmac_sha256_match: false,
        aes_gcm_authenticated: false,
        attestation_valid: declaredState === "UNKNOWN" && envelope.attestation === null,
        attestation_trusted: false,
        fault_codes: faults
      });
      continue;
    }

    if (!envelope.seal) {
      demote("ERR_MISSING_SEAL", "sealed payload has no CryptographicSeal");
    } else {
      try {
        const slotKey = deriveSlotKey(
          masterSecretHex,
          envelope.seal.hkdf_salt,
          dossier.tenant_id,
          dossier.dossier_id,
          slotId
        );
        const canonical = canonicalizeJCS(envelope.payload);
        const expectedJcsSha = sha256Hex(Buffer.from(canonical, UTF8));
        payloadJcsSha = expectedJcsSha;
        const expectedHmac = computeSlotDigest(slotKey, envelope.payload);

        jcsMatch = expectedJcsSha === envelope.seal.jcs_sha256;
        hmacMatch = expectedHmac === envelope.seal.hmac_sha256;

        if (!jcsMatch || !hmacMatch) {
          demote(
            "ERR_SEAL_INTEGRITY_FAILURE",
            `HMAC-SHA256/JCS digest mismatch (expected ${expectedHmac}, found ${envelope.seal.hmac_sha256})`
          );
        }

        try {
          const decipher = crypto.createDecipheriv(
            "aes-256-gcm",
            slotKey,
            assertHex(envelope.seal.aes_gcm_iv, 12, "aes_gcm_iv")
          );
          decipher.setAAD(
            Buffer.from(`${dossier.dossier_id}|${slotId}|${declaredState}`, UTF8)
          );
          decipher.setAuthTag(assertHex(envelope.seal.aes_gcm_tag, 16, "aes_gcm_tag"));
          const plaintext = Buffer.concat([
            decipher.update(assertHex(envelope.seal.aes_gcm_ciphertext, envelope.seal.aes_gcm_ciphertext.length / 2, "aes_gcm_ciphertext")),
            decipher.final()
          ]).toString(UTF8);
          aesAuthenticated = plaintext === canonical;
          if (!aesAuthenticated) {
            demote("ERR_AES_GCM_AUTH_FAILURE", "AES-GCM plaintext does not match the sealed payload");
          }
        } catch {
          demote("ERR_AES_GCM_AUTH_FAILURE", "AES-GCM authentication failed");
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "unknown crypto failure";
        demote("ERR_SEAL_INTEGRITY_FAILURE", `cryptographic verification failed: ${message}`);
      }
    }

    let attestationTrusted = false;
    if (declaredState !== "UNKNOWN") {
      if (!envelope.attestation) {
        demote("ERR_ATTESTATION_MISSING", "sealed slot has no attestation metadata");
      } else {
        const attestation = envelope.attestation;
        const expiresAt = Date.parse(attestation.expires_at);
        if (!Number.isFinite(expiresAt)) {
          demote("ERR_ATTESTATION_EXPIRED", "attestation expiry timestamp is invalid");
        } else if (expiresAt < parsedReference) {
          demote(
            "ERR_ATTESTATION_EXPIRED",
            `attestation expired at ${attestation.expires_at}`
          );
        }

        if (attestation.signature_algorithm !== "Ed25519") {
          demote(
            "ERR_ATTESTATION_SIGNATURE_INVALID",
            "attestation signature_algorithm must be Ed25519"
          );
        }

        if (!/^[0-9a-f]{64}$/.test(attestation.attester_public_key_hex)) {
          demote(
            "ERR_ATTESTATION_SIGNATURE_INVALID",
            "attester_public_key_hex must be 32 bytes of lowercase hexadecimal"
          );
        }

        if (!/^[0-9a-f]{128}$/.test(attestation.signature_hex)) {
          demote(
            "ERR_ATTESTATION_SIGNATURE_INVALID",
            "attestation signature_hex must be 64 bytes of lowercase hexadecimal"
          );
        }

        if (attestation.payload_jcs_sha256 !== payloadJcsSha) {
          demote(
            "ERR_ATTESTATION_PAYLOAD_MISMATCH",
            "attestation payload_jcs_sha256 does not match the sealed payload"
          );
        }

        if (
          !verifyAttestationSignature(slotId, payloadJcsSha, attestation)
        ) {
          demote(
            "ERR_ATTESTATION_SIGNATURE_INVALID",
            "Ed25519 attestation signature does not verify"
          );
        }

        attestationTrusted = isTrustedAttester(
          trustStore,
          attestation,
          slotId,
          referenceTime
        );

        if (
          declaredState === "CORROBORATED" &&
          (attestation.attester_type === "PARTY_SELF_DECLARATION" ||
            !attestation.accreditation_id)
        ) {
          demote(
            "ERR_ATTESTATION_ACCREDITATION_REQUIRED",
            "CORROBORATED requires an independent accredited attester"
          );
        } else if (declaredState === "CORROBORATED" && !attestationTrusted) {
          demote(
            "ERR_ATTESTATION_UNTRUSTED",
            "CORROBORATED requires an attester key present in the relying party's trust store"
          );
        }
      }
    }

    const attestationValid = !faults.some((code) => code.startsWith("ERR_ATTESTATION"));
    reports.push({
      slot_id: slotId,
      layer,
      declared_state: declaredState,
      effective_state: effectiveState,
      jcs_sha256_match: jcsMatch,
      hmac_sha256_match: hmacMatch,
      aes_gcm_authenticated: aesAuthenticated,
      attestation_valid: attestationValid,
      attestation_trusted: attestationTrusted && attestationValid,
      fault_codes: faults
    });
  }

  const allSealsValid = reports.every((slot) => slot.fault_codes.length === 0);
  return {
    dossier_id: dossier.dossier_id,
    reference_time: referenceTime,
    ok: allSealsValid,
    all_seals_valid: allSealsValid,
    slots: reports,
    errors
  };
}

export function haversineMeters(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number {
  const earthRadiusMeters = 6_371_008.8;
  const toRadians = (degrees: number): number => (degrees * Math.PI) / 180;
  const deltaLat = toRadians(lat2 - lat1);
  const deltaLon = toRadians(lon2 - lon1);
  const a =
    Math.sin(deltaLat / 2) ** 2 +
    Math.cos(toRadians(lat1)) * Math.cos(toRadians(lat2)) * Math.sin(deltaLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return earthRadiusMeters * c;
}

function evaluateStateRequirements(
  mandatorySlots: readonly string[],
  effectiveStates: Map<string, EpistemicState>,
  reportsById: Map<string, SlotSealReport>
): { uncorroborated: string[]; haltReasons: HaltReason[]; states: Record<string, EpistemicState> } {
  const uncorroborated: string[] = [];
  const haltReasons: HaltReason[] = [];
  const states: Record<string, EpistemicState> = {};

  for (const slotId of mandatorySlots) {
    const state = effectiveStates.get(slotId) ?? "UNKNOWN";
    states[slotId] = state;
    if (state === "CORROBORATED") {
      continue;
    }
    uncorroborated.push(slotId);

    const report = reportsById.get(slotId);
    if (report?.fault_codes.includes("ERR_SEAL_INTEGRITY_FAILURE")) {
      haltReasons.push({
        code: "ERR_SEAL_INTEGRITY_FAILURE",
        slot_id: slotId,
        detail: "Cryptographic seal failed; slot was demoted to UNKNOWN."
      });
    }
    if (report?.fault_codes.includes("ERR_ATTESTATION_EXPIRED")) {
      haltReasons.push({
        code: "ERR_ATTESTATION_EXPIRED",
        slot_id: slotId,
        detail: "Attestation is outside its validity window; slot was demoted to UNKNOWN."
      });
    }
    const attestationFaultDetails: Record<string, string> = {
      ERR_ATTESTATION_SIGNATURE_INVALID:
        "Ed25519 attestation signature is malformed or does not verify.",
      ERR_ATTESTATION_PAYLOAD_MISMATCH:
        "Attestation payload hash does not match the sealed payload.",
      ERR_ATTESTATION_UNTRUSTED:
        "Attester key is absent from the relying party's trust store."
    };
    for (const [code, detail] of Object.entries(attestationFaultDetails)) {
      if (report?.fault_codes.includes(code)) {
        haltReasons.push({ code, slot_id: slotId, detail });
      }
    }
    haltReasons.push({
      code: state === "ASSERTED" ? "ERR_SLOT_ASSERTED" : "ERR_SLOT_UNKNOWN",
      slot_id: slotId,
      detail:
        state === "ASSERTED"
          ? "Slot is self-declared and lacks independent third-party corroboration."
          : "Slot is missing, unsubmitted, expired, or cryptographically invalid."
    });
  }

  return { uncorroborated, haltReasons, states };
}

function addSemanticCheckRaw(
  checks: SemanticCheck[],
  haltReasons: HaltReason[],
  ruleId: string,
  sourceSlots: string[],
  status: SemanticStatus,
  detail: string,
  failureCode: string | undefined,
  effectiveStates: Map<string, EpistemicState>
): void {
  let finalStatus = status;
  let finalDetail = detail;
  const uncorroboratedSources = sourceSlots.filter(
    (slotId) => effectiveStates.get(slotId) !== "CORROBORATED"
  );
  if (finalStatus !== "NOT_EVALUATED" && uncorroboratedSources.length > 0) {
    finalStatus = "NOT_EVALUATED";
    finalDetail = `Source slot(s) not corroborated: ${uncorroboratedSources.join(", ")}.`;
  }
  checks.push({
    rule_id: ruleId,
    source_slots: sourceSlots,
    status: finalStatus,
    detail: finalDetail
  });
  if (finalStatus === "FAIL" && failureCode) {
    haltReasons.push({
      code: failureCode,
      slot_id: sourceSlots[0] ?? null,
      detail: finalDetail
    });
  }
}

function combineStatuses(statuses: SemanticStatus[]): SemanticStatus {
  if (statuses.some((status) => status === "FAIL")) {
    return "FAIL";
  }
  if (statuses.some((status) => status === "NOT_EVALUATED")) {
    return "NOT_EVALUATED";
  }
  return "PASS";
}

function findCheck(checks: SemanticCheck[], ruleId: string): SemanticCheck | undefined {
  return checks.find((check) => check.rule_id === ruleId);
}

function buildInstitutionalViews(
  dossier: OOES18Dossier,
  referenceTime: string,
  gate1: GateResult,
  gate2: GateResult,
  effectiveStates: Map<string, EpistemicState>
): InstitutionalViews {
  const s01 = payloadOf(dossier, "L1.S01_PURCHASE_ORDER");
  const s14 = payloadOf(dossier, "L5.S14_LANDED_VALUATION");
  const s16 = payloadOf(dossier, "L5.S16_PSI_REPORT");

  const totalAmount = numberOf(s01, "total_amount");
  const currency = stringOf(s01, "currency") ?? "EUR";
  const advanceAmount =
    totalAmount === null ? 0 : Math.round(totalAmount * 0.3 * 100) / 100;

  const preWireGate: PreWireGateView = {
    gate_id: gate1.gate_id,
    verdict: gate1.verdict,
    advance_amount_eur: advanceAmount,
    currency,
    mandatory_slots: [...gate1.mandatory_slots],
    uncorroborated_slots: [...gate1.uncorroborated_slots],
    halt_reasons: [...gate1.halt_reasons],
    generated_at: referenceTime
  };

  const containerCheck = findCheck(gate2.semantic_checks, "G2_CONTAINER_S10_S11");
  const cleanCheck = findCheck(gate2.semantic_checks, "G2_CLEAN_ON_BOARD_S11");
  const originCheck = findCheck(gate2.semantic_checks, "G2_ORIGIN_S04_S12");
  const rexCheck = findCheck(gate2.semantic_checks, "G2_REX_S05_S12");

  const art14d = combineStatuses([
    containerCheck?.status ?? "NOT_EVALUATED",
    originCheck?.status ?? "NOT_EVALUATED",
    rexCheck?.status ?? "NOT_EVALUATED"
  ]);

  let art18Status: SemanticStatus = "NOT_EVALUATED";
  let art18Detail = "Commercial invoice valuation slot L5.S14 is not corroborated.";
  if (
    s01 !== null &&
    s14 !== null &&
    effectiveStates.get("L1.S01_PURCHASE_ORDER") === "CORROBORATED" &&
    effectiveStates.get("L5.S14_LANDED_VALUATION") === "CORROBORATED"
  ) {
    const fob = numberOf(s14, "fob_value_eur");
    const invoiceCurrency = stringOf(s01, "currency");
    const invoiceAmount = numberOf(s01, "total_amount");
    if (fob !== null && invoiceAmount !== null && invoiceCurrency === "EUR") {
      if (Math.abs(fob - invoiceAmount) <= 0.01) {
        art18Status = "PASS";
        art18Detail = "Invoice FOB value agrees with the purchase order total within EUR 0.01.";
      } else {
        art18Status = "FAIL";
        art18Detail = `Invoice FOB ${fob.toFixed(2)} EUR does not agree with PO total ${invoiceAmount.toFixed(2)} EUR.`;
      }
    } else {
      art18Detail = "Invoice currency or amount is not reconcilable.";
    }
  }

  const art20 = combineStatuses([
    containerCheck?.status ?? "NOT_EVALUATED",
    cleanCheck?.status ?? "NOT_EVALUATED"
  ]);

  let art30Status: SemanticStatus = "NOT_EVALUATED";
  let art30Detail = "Pre-shipment inspection report L5.S16 is not corroborated.";
  const poUnits = numberOf(s01, "total_units");
  const verifiedUnits = numberOf(s16, "verified_units_count");
  if (
    poUnits !== null &&
    verifiedUnits !== null &&
    poUnits > 0 &&
    effectiveStates.get("L5.S16_PSI_REPORT") === "CORROBORATED"
  ) {
    const deviation = Math.abs(verifiedUnits - poUnits) / poUnits;
    if (deviation <= 0.05) {
      art30Status = "PASS";
      art30Detail = `Verified quantity deviates ${(deviation * 100).toFixed(2)}% from the PO, inside the UCP 600 Art. 30 5% tolerance.`;
    } else {
      art30Status = "FAIL";
      art30Detail = `Verified quantity deviates ${(deviation * 100).toFixed(2)}% from the PO, outside the UCP 600 Art. 30 5% tolerance.`;
    }
  }

  const lcChecks: LcCheck[] = [
    {
      reference: "UCP 600 Art. 14(d)",
      requirement:
        "Data in a document, when read in context, must not conflict with data in any other stipulated document.",
      source_slots: [
        "L4.S10_BOLT_SEAL",
        "L4.S11_BILL_OF_LADING",
        "L4.S12_CERTIFICATE_OF_ORIGIN",
        "L2.S04_SUPPLIER_KYB",
        "L2.S05_REGISTRY_STANDING"
      ],
      status: art14d,
      detail:
        art14d === "PASS"
          ? "Container, origin, and REX identifier data are mutually non-contradictory."
          : "One or more cross-document data elements are missing or contradictory."
    },
    {
      reference: "UCP 600 Art. 18 / ISBP 821 Para. C1",
      requirement:
        "A commercial invoice must appear on its face to have been issued by the beneficiary and be made out in the currency of the credit.",
      source_slots: ["L1.S01_PURCHASE_ORDER", "L5.S14_LANDED_VALUATION"],
      status: art18Status,
      detail: art18Detail
    },
    {
      reference: "UCP 600 Art. 20 / ISBP 821 Para. E1",
      requirement:
        "A bill of lading must indicate goods have been shipped on board a named vessel and be clean.",
      source_slots: ["L4.S10_BOLT_SEAL", "L4.S11_BILL_OF_LADING"],
      status: art20,
      detail:
        art20 === "PASS"
          ? "Container continuity holds and the transport document is clean on board."
          : "Transport document continuity or clean-on-board status is not established."
    },
    {
      reference: "UCP 600 Art. 27",
      requirement: "A transport document must not bear a clause declaring a defective condition of the goods or packaging.",
      source_slots: ["L4.S11_BILL_OF_LADING"],
      status: cleanCheck?.status ?? "NOT_EVALUATED",
      detail: cleanCheck?.detail ?? "Bill of lading is not available."
    },
    {
      reference: "UCP 600 Art. 30",
      requirement:
        "A tolerance not exceeding 5% above or below the quantity stated is permissible when the credit does not stipulate a quantity in packing units or individual items.",
      source_slots: ["L1.S01_PURCHASE_ORDER", "L5.S16_PSI_REPORT"],
      status: art30Status,
      detail: art30Detail
    },
    {
      reference: "ISBP 821 Para. L1",
      requirement:
        "A certificate of origin must be consistent with the invoice and the transport document as to origin and consignee data.",
      source_slots: [
        "L2.S04_SUPPLIER_KYB",
        "L2.S05_REGISTRY_STANDING",
        "L4.S12_CERTIFICATE_OF_ORIGIN"
      ],
      status: combineStatuses([
        originCheck?.status ?? "NOT_EVALUATED",
        rexCheck?.status ?? "NOT_EVALUATED"
      ]),
      detail:
        originCheck?.status === "PASS" && rexCheck?.status === "PASS"
          ? "Origin country and exporter REX identifier are consistent across documents."
          : "Origin country or REX identifier consistency is not established."
    },
  ];

  const lcOverall: LcMt700CheckView["overall"] = lcChecks.some(
    (check) => check.status === "FAIL"
  )
    ? "DISCREPANT"
    : lcChecks.some((check) => check.status === "NOT_EVALUATED")
      ? "INCOMPLETE"
      : "CLEAN";

  const lcMt700Check: LcMt700CheckView = {
    profile: "UCP_600_ISBP_821",
    overall: lcOverall,
    checks: lcChecks,
    generated_at: referenceTime
  };

  const statusFor = (slotIds: string[]): DeltaDataElement["status"] => {
    const anyPayload = slotIds.some((slotId) => payloadOf(dossier, slotId) !== null);
    const allCorroborated = slotIds.every(
      (slotId) => effectiveStates.get(slotId) === "CORROBORATED"
    );
    if (allCorroborated) {
      return "COMPLETE";
    }
    return anyPayload ? "PENDING" : "MISSING";
  };

  const s04 = payloadOf(dossier, "L2.S04_SUPPLIER_KYB");
  const s05 = payloadOf(dossier, "L2.S05_REGISTRY_STANDING");
  const s10 = payloadOf(dossier, "L4.S10_BOLT_SEAL");
  const s11 = payloadOf(dossier, "L4.S11_BILL_OF_LADING");
  const s12 = payloadOf(dossier, "L4.S12_CERTIFICATE_OF_ORIGIN");
  const s15 = payloadOf(dossier, "L5.S15_DUTY_CALCULATION");

  const deltaDataElements: DeltaDataElement[] = [
    {
      de: "DE 11 01",
      name: "Declaration type (H1 release for free circulation)",
      source_slots: ["L5.S15_DUTY_CALCULATION"],
      status: statusFor(["L5.S15_DUTY_CALCULATION"]),
      values: {
        declaration_type: "H1",
        taric_10_code: stringOf(s15, "taric_10_code"),
        preference_code: stringOf(s15, "preference_code")
      }
    },
    {
      de: "DE 12 03",
      name: "Supporting documents (N380 invoice, N705 B/L, U164/N865 origin, ISO 17025 lab, forced-labour attestation)",
      source_slots: [
        "L1.S01_PURCHASE_ORDER",
        "L3.S09_LAB_CERTIFICATE",
        "L4.S11_BILL_OF_LADING",
        "L4.S12_CERTIFICATE_OF_ORIGIN",
        "L5.S14_LANDED_VALUATION"
      ],
      status: statusFor([
        "L1.S01_PURCHASE_ORDER",
        "L3.S09_LAB_CERTIFICATE",
        "L4.S11_BILL_OF_LADING",
        "L4.S12_CERTIFICATE_OF_ORIGIN",
        "L5.S14_LANDED_VALUATION"
      ]),
      values: {
        invoice_number: stringOf(s14, "invoice_number"),
        bill_of_lading: stringOf(s11, "bl_number"),
        lab_report_number: stringOf(payloadOf(dossier, "L3.S09_LAB_CERTIFICATE"), "report_number"),
        origin_certificate: stringOf(s12, "coo_number")
      }
    },
    {
      de: "DE 13 01",
      name: "Exporter identity and address",
      source_slots: ["L2.S04_SUPPLIER_KYB"],
      status: statusFor(["L2.S04_SUPPLIER_KYB"]),
      values: {
        legal_name: stringOf(s04, "legal_name"),
        tax_registration_id: stringOf(s04, "tax_registration_id"),
        country_iso2: stringOf(s04, "country_iso2")
      }
    },
    {
      de: "DE 13 04",
      name: "Importer EORI",
      source_slots: ["L1.S01_PURCHASE_ORDER"],
      status: statusFor(["L1.S01_PURCHASE_ORDER"]),
      values: {
        buyer_eori: stringOf(s01, "buyer_eori")
      }
    },
    {
      de: "DE 14 03",
      name: "Customs value and Incoterms addition/deduction breakdown (UCC Art. 70/71)",
      source_slots: ["L5.S14_LANDED_VALUATION"],
      status: statusFor(["L5.S14_LANDED_VALUATION"]),
      values: {
        fob_value_eur: numberOf(s14, "fob_value_eur"),
        international_freight_eur: numberOf(s14, "international_freight_eur"),
        insurance_eur: numberOf(s14, "insurance_eur"),
        cif_customs_value_eur: numberOf(s14, "cif_customs_value_eur"),
        valuation_method: stringOf(s14, "valuation_method")
      }
    },
    {
      de: "DE 16 08 / 16 09",
      name: "Country of non-preferential and preferential origin",
      source_slots: ["L4.S12_CERTIFICATE_OF_ORIGIN"],
      status: statusFor(["L4.S12_CERTIFICATE_OF_ORIGIN"]),
      values: {
        country_of_origin_iso2: stringOf(s12, "country_of_origin_iso2"),
        origin_criterion: stringOf(s12, "origin_criterion"),
        origin_regime: stringOf(s12, "origin_regime"),
        proof_type: stringOf(s12, "proof_type"),
        exporter_rex_id: stringOf(s12, "exporter_rex_id")
      }
    },
    {
      de: "DE 18 09",
      name: "Commodity code (10-digit EU TARIC)",
      source_slots: ["L5.S15_DUTY_CALCULATION"],
      status: statusFor(["L5.S15_DUTY_CALCULATION"]),
      values: {
        taric_10_code: stringOf(s15, "taric_10_code"),
        mfn_duty_rate_pct: numberOf(s15, "mfn_duty_rate_pct"),
        preferential_duty_rate_pct: numberOf(s15, "preferential_duty_rate_pct"),
        calculated_duty_eur: numberOf(s15, "calculated_duty_eur"),
        calculated_vat_eur: numberOf(s15, "calculated_vat_eur")
      }
    },
    {
      de: "DE 19 01 / 19 07",
      name: "Container identification and ISO 17712 seal number",
      source_slots: ["L4.S10_BOLT_SEAL", "L4.S11_BILL_OF_LADING"],
      status: statusFor(["L4.S10_BOLT_SEAL", "L4.S11_BILL_OF_LADING"]),
      values: {
        container_number: stringOf(s10, "container_number"),
        seal_serial_number: stringOf(s10, "seal_serial_number"),
        iso17712_clause_6_compliant: booleanOf(s10, "iso17712_clause_6_compliant")
      }
    }
  ];

  const deltaIeH1Pack: DeltaIeH1PackView = {
    declaration_type: "H1",
    entry_process: "DELTA_IE_VOLET_IMPORT_H1",
    overall: deltaDataElements.every((element) => element.status === "COMPLETE")
      ? "READY"
      : "INCOMPLETE",
    data_elements: deltaDataElements,
    generated_at: referenceTime
  };

  return {
    pre_wire_gate: preWireGate,
    lc_mt700_check: lcMt700Check,
    delta_ie_h1_pack: deltaIeH1Pack
  };
}

/**
 * Deterministic two-gate release decision.
 *
 * Invariant 2.1: Gamma : D -> {READY, HARD_STOP} x P(R_halt)
 * Every verdict is a pure function of the canonical dossier.
 */
export function evaluateReleaseGates(
  dossier: OOES18Dossier,
  masterSecretHex: string,
  referenceTime: string = dossier.reference_time,
  trustStore?: AttesterTrustStore
): GateEvaluationReport {
  const sealVerification = verifyDossierSeals(
    dossier,
    masterSecretHex,
    referenceTime,
    trustStore
  );
  const reportsById = new Map(
    sealVerification.slots.map((slot) => [slot.slot_id, slot] as const)
  );
  const effectiveStates = new Map<string, EpistemicState>(
    sealVerification.slots.map((slot) => [slot.slot_id, slot.effective_state] as const)
  );

  const addSemanticCheck = (
    checks: SemanticCheck[],
    haltReasons: HaltReason[],
    ruleId: string,
    sourceSlots: string[],
    status: SemanticStatus,
    detail: string,
    failureCode?: string
  ): void => {
    addSemanticCheckRaw(
      checks,
      haltReasons,
      ruleId,
      sourceSlots,
      status,
      detail,
      failureCode,
      effectiveStates
    );
  };

  const gate1Mandatory = [
    "L1.S01_PURCHASE_ORDER",
    "L1.S02_TECH_PACK",
    "L1.S03_GOLDEN_SAMPLE",
    "L2.S04_SUPPLIER_KYB",
    "L2.S05_REGISTRY_STANDING",
    "L2.S06_CAPACITY_ATTESTATION"
  ];

  const gate1StateResult = evaluateStateRequirements(
    gate1Mandatory,
    effectiveStates,
    reportsById
  );
  const gate1Semantics: SemanticCheck[] = [];
  const gate1HaltReasons: HaltReason[] = [...gate1StateResult.haltReasons];

  const s05 = payloadOf(dossier, "L2.S05_REGISTRY_STANDING");
  const s06 = payloadOf(dossier, "L2.S06_CAPACITY_ATTESTATION");

  if (s05 === null) {
    addSemanticCheck(
      gate1Semantics,
      gate1HaltReasons,
      "G1_SANCTIONS_CLEAR",
      ["L2.S05_REGISTRY_STANDING"],
      "NOT_EVALUATED",
      "Registry standing payload is unavailable."
    );
    addSemanticCheck(
      gate1Semantics,
      gate1HaltReasons,
      "G1_FORCED_LABOUR_SCREENING",
      ["L2.S05_REGISTRY_STANDING"],
      "NOT_EVALUATED",
      "Registry standing payload is unavailable."
    );
  } else {
    const sanctionsClear = booleanOf(s05, "sanctions_clear");
    addSemanticCheck(
      gate1Semantics,
      gate1HaltReasons,
      "G1_SANCTIONS_CLEAR",
      ["L2.S05_REGISTRY_STANDING"],
      sanctionsClear === true ? "PASS" : "FAIL",
      sanctionsClear === true
        ? "Supplier is not subject to an enumerated sanctions restriction."
        : "Supplier sanctions status is not explicitly clear.",
      "ERR_SEMANTIC_SANCTIONS_NOT_CLEAR"
    );

    const screening = stringOf(s05, "eu_2024_3015_screening_status");
    addSemanticCheck(
      gate1Semantics,
      gate1HaltReasons,
      "G1_FORCED_LABOUR_SCREENING",
      ["L2.S05_REGISTRY_STANDING"],
      screening === "CLEAR" ? "PASS" : "FAIL",
      screening === "CLEAR"
        ? "EU Regulation 2024/3015 screening status is CLEAR."
        : `EU Regulation 2024/3015 screening status is ${screening ?? "absent"}.`,
      "ERR_SEMANTIC_FORCED_LABOUR_SCREENING"
    );
  }

  if (s06 === null) {
    addSemanticCheck(
      gate1Semantics,
      gate1HaltReasons,
      "G1_SUBCONTRACTING_BAN",
      ["L2.S06_CAPACITY_ATTESTATION"],
      "NOT_EVALUATED",
      "Capacity attestation payload is unavailable."
    );
    addSemanticCheck(
      gate1Semantics,
      gate1HaltReasons,
      "G1_CAPACITY_POSITIVE",
      ["L2.S06_CAPACITY_ATTESTATION"],
      "NOT_EVALUATED",
      "Capacity attestation payload is unavailable."
    );
  } else {
    const subcontracting = booleanOf(s06, "subcontracting_authorized");
    addSemanticCheck(
      gate1Semantics,
      gate1HaltReasons,
      "G1_SUBCONTRACTING_BAN",
      ["L2.S06_CAPACITY_ATTESTATION"],
      subcontracting === false ? "PASS" : "FAIL",
      subcontracting === false
        ? "Subcontracting is explicitly unauthorized."
        : "Subcontracting is authorized or undeclared, blocking the pre-wire gate.",
      "ERR_SEMANTIC_SUBCONTRACTING_AUTHORIZED"
    );

    const capacity = numberOf(s06, "daily_output_capacity_units");
    addSemanticCheck(
      gate1Semantics,
      gate1HaltReasons,
      "G1_CAPACITY_POSITIVE",
      ["L2.S06_CAPACITY_ATTESTATION"],
      capacity !== null && capacity > 0 ? "PASS" : "FAIL",
      capacity !== null && capacity > 0
        ? `Declared daily capacity is ${capacity} units.`
        : "Declared daily output capacity is absent or non-positive.",
      "ERR_SEMANTIC_CAPACITY_ZERO"
    );
  }

  const gate1SemanticsOk = gate1Semantics.every((check) => check.status !== "FAIL");
  const gate1: GateResult = {
    gate_id: "GATE_01_DEPOSIT_PRE_WIRE",
    verdict:
      gate1StateResult.uncorroborated.length === 0 && gate1SemanticsOk
        ? "READY"
        : "HARD_STOP",
    mandatory_slots: gate1Mandatory,
    uncorroborated_slots: gate1StateResult.uncorroborated,
    slot_states: gate1StateResult.states,
    halt_reasons: gate1HaltReasons,
    semantic_checks: gate1Semantics,
    semantics_ok: gate1SemanticsOk
  };

  const gate2Mandatory = [
    "L1.S01_PURCHASE_ORDER",
    "L1.S02_TECH_PACK",
    "L1.S03_GOLDEN_SAMPLE",
    "L2.S04_SUPPLIER_KYB",
    "L2.S05_REGISTRY_STANDING",
    "L3.S07_PRODUCTION_PHOTOS",
    "L3.S08_INLINE_AQL",
    "L3.S09_LAB_CERTIFICATE",
    "L4.S10_BOLT_SEAL",
    "L4.S11_BILL_OF_LADING",
    "L4.S12_CERTIFICATE_OF_ORIGIN",
    "L5.S14_LANDED_VALUATION",
    "L5.S15_DUTY_CALCULATION",
    "L5.S16_PSI_REPORT"
  ];

  const gate2StateResult = evaluateStateRequirements(
    gate2Mandatory,
    effectiveStates,
    reportsById
  );
  const gate2Semantics: SemanticCheck[] = [];
  const gate2HaltReasons: HaltReason[] = [...gate2StateResult.haltReasons];

  const s02 = payloadOf(dossier, "L1.S02_TECH_PACK");
  const s04 = payloadOf(dossier, "L2.S04_SUPPLIER_KYB");
  const s07 = payloadOf(dossier, "L3.S07_PRODUCTION_PHOTOS");
  const s08 = payloadOf(dossier, "L3.S08_INLINE_AQL");
  const s09 = payloadOf(dossier, "L3.S09_LAB_CERTIFICATE");
  const s10 = payloadOf(dossier, "L4.S10_BOLT_SEAL");
  const s11 = payloadOf(dossier, "L4.S11_BILL_OF_LADING");
  const s12 = payloadOf(dossier, "L4.S12_CERTIFICATE_OF_ORIGIN");
  const s14 = payloadOf(dossier, "L5.S14_LANDED_VALUATION");
  const s15 = payloadOf(dossier, "L5.S15_DUTY_CALCULATION");

  const s04Lat = numberOf(s04, "factory_lat");
  const s04Lon = numberOf(s04, "factory_lon");
  const s07Lat = numberOf(s07, "exif_gps_lat");
  const s07Lon = numberOf(s07, "exif_gps_lon");
  if (s04Lat === null || s04Lon === null || s07Lat === null || s07Lon === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_GEOFENCE_S04_S07",
      ["L2.S04_SUPPLIER_KYB", "L3.S07_PRODUCTION_PHOTOS"],
      "NOT_EVALUATED",
      "Factory or EXIF GPS coordinates are unavailable."
    );
  } else {
    const distance = haversineMeters(s04Lat, s04Lon, s07Lat, s07Lon);
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_GEOFENCE_S04_S07",
      ["L2.S04_SUPPLIER_KYB", "L3.S07_PRODUCTION_PHOTOS"],
      distance <= 500 ? "PASS" : "FAIL",
      `Haversine distance between factory KYB coordinates and inline media EXIF coordinates is ${distance.toFixed(1)} m (limit 500 m).`,
      "ERR_SEMANTIC_GEOFENCE_DISTANCE"
    );
  }

  const s10Lat = numberOf(s10, "stuffing_lat");
  const s10Lon = numberOf(s10, "stuffing_lon");
  const stuffingLocationType = stringOf(s10, "stuffing_location_type");
  if (s10Lat === null || s10Lon === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_GEOFENCE_S04_S10",
      ["L2.S04_SUPPLIER_KYB", "L4.S10_BOLT_SEAL"],
      "NOT_EVALUATED",
      "Stuffing coordinates are unavailable in the bolt-seal slot."
    );
  } else if (stuffingLocationType === "PORT") {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_GEOFENCE_S04_S10",
      ["L2.S04_SUPPLIER_KYB", "L4.S10_BOLT_SEAL"],
      "NOT_EVALUATED",
      "Port-side stuffing is declared; the factory geofence does not apply."
    );
  } else if (stuffingLocationType !== "FACTORY") {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_GEOFENCE_S04_S10",
      ["L2.S04_SUPPLIER_KYB", "L4.S10_BOLT_SEAL"],
      "FAIL",
      "Stuffing location type is absent or not FACTORY/PORT.",
      "ERR_SEMANTIC_STUFFING_GEOFENCE"
    );
  } else if (s04Lat === null || s04Lon === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_GEOFENCE_S04_S10",
      ["L2.S04_SUPPLIER_KYB", "L4.S10_BOLT_SEAL"],
      "NOT_EVALUATED",
      "Factory coordinates are unavailable for the stuffing geofence."
    );
  } else {
    const distance = haversineMeters(s04Lat, s04Lon, s10Lat, s10Lon);
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_GEOFENCE_S04_S10",
      ["L2.S04_SUPPLIER_KYB", "L4.S10_BOLT_SEAL"],
      distance <= 500 ? "PASS" : "FAIL",
      `Haversine distance between factory KYB coordinates and container stuffing coordinates is ${distance.toFixed(1)} m (limit 500 m).`,
      "ERR_SEMANTIC_STUFFING_GEOFENCE"
    );
  }

  if (s08 === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_AQL_S08",
      ["L3.S08_INLINE_AQL"],
      "NOT_EVALUATED",
      "Inline AQL inspection payload is unavailable."
    );
  } else {
    const result = stringOf(s08, "result");
    const critical = numberOf(s08, "critical_defects");
    const major = numberOf(s08, "major_defects");
    const maxMajor = numberOf(s08, "max_allowed_major");
    if (result === null || critical === null || major === null || maxMajor === null) {
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_AQL_S08",
        ["L3.S08_INLINE_AQL"],
        "FAIL",
        "Inline AQL payload is incomplete.",
        "ERR_SEMANTIC_AQL_FAIL"
      );
    } else if (result !== "PASS") {
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_AQL_S08",
        ["L3.S08_INLINE_AQL"],
        "FAIL",
        `ISO 2859-1 inspection result is ${result}, not PASS.`,
        "ERR_SEMANTIC_AQL_FAIL"
      );
    } else if (critical !== 0) {
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_AQL_S08",
        ["L3.S08_INLINE_AQL"],
        "FAIL",
        `Critical defect count is ${critical}; zero is mandatory.`,
        "ERR_SEMANTIC_CRITICAL_DEFECTS"
      );
    } else if (major > maxMajor) {
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_AQL_S08",
        ["L3.S08_INLINE_AQL"],
        "FAIL",
        `Major defects ${major} exceed the AQL acceptance number ${maxMajor}.`,
        "ERR_SEMANTIC_MAJOR_DEFECTS"
      );
    } else {
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_AQL_S08",
        ["L3.S08_INLINE_AQL"],
        "PASS",
        `ISO 2859-1 AQL 2.5 inspection passed: 0 critical, ${major} major defects against a limit of ${maxMajor}.`
      );
    }
  }

  if (s09 === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_REACH_S09",
      ["L3.S09_LAB_CERTIFICATE"],
      "NOT_EVALUATED",
      "Laboratory certificate payload is unavailable."
    );
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_AZO_S09",
      ["L3.S09_LAB_CERTIFICATE"],
      "NOT_EVALUATED",
      "Laboratory certificate payload is unavailable."
    );
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_FIBER_S09_S02",
      ["L3.S09_LAB_CERTIFICATE", "L1.S02_TECH_PACK"],
      "NOT_EVALUATED",
      "Laboratory certificate or technical pack payload is unavailable."
    );
  } else {
    const reach = booleanOf(s09, "reach_annex_xvii_compliant");
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_REACH_S09",
      ["L3.S09_LAB_CERTIFICATE"],
      reach === true ? "PASS" : "FAIL",
      reach === true
        ? "REACH Annex XVII compliance is attested by the ISO/IEC 17025 laboratory."
        : "REACH Annex XVII compliance is not attested.",
      "ERR_SEMANTIC_REACH_NONCOMPLIANT"
    );

    const azoPpm = numberOf(s09, "azo_dyes_ppm");
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_AZO_S09",
      ["L3.S09_LAB_CERTIFICATE"],
      azoPpm !== null && azoPpm < 30 ? "PASS" : "FAIL",
      azoPpm !== null
        ? `Azo dye concentration is ${azoPpm} ppm (limit < 30 ppm).`
        : "Azo dye concentration is absent.",
      "ERR_SEMANTIC_AZO_DYES"
    );

    const cotton = numberOf(s09, "measured_cotton_pct");
    if (cotton === null) {
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_FIBER_S09_S02",
        ["L3.S09_LAB_CERTIFICATE", "L1.S02_TECH_PACK"],
        "FAIL",
        "Measured cotton percentage is absent.",
        "ERR_SEMANTIC_FIBER_TOLERANCE"
      );
    } else {
      const deviation = Math.abs(cotton - 100);
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_FIBER_S09_S02",
        ["L3.S09_LAB_CERTIFICATE", "L1.S02_TECH_PACK"],
        deviation <= 3.0 ? "PASS" : "FAIL",
        `Measured cotton content ${cotton}% deviates ${deviation.toFixed(1)} percentage points from the 100% specification (tolerance 3.0).`,
        "ERR_SEMANTIC_FIBER_TOLERANCE"
      );
    }
  }

  const s10Container = stringOf(s10, "container_number");
  const s11Container = stringOf(s11, "container_number");
  if (s10Container === null || s11Container === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_CONTAINER_S10_S11",
      ["L4.S10_BOLT_SEAL", "L4.S11_BILL_OF_LADING"],
      "NOT_EVALUATED",
      "Container number is unavailable in the seal or transport slot."
    );
  } else {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_CONTAINER_S10_S11",
      ["L4.S10_BOLT_SEAL", "L4.S11_BILL_OF_LADING"],
      s10Container === s11Container ? "PASS" : "FAIL",
      s10Container === s11Container
        ? `Container ${s10Container} is continuous between the seal and bill of lading.`
        : `Container mismatch: seal ${s10Container} versus bill of lading ${s11Container}.`,
      "ERR_SEMANTIC_CONTAINER_MISMATCH"
    );
  }

  const scacCode = stringOf(s11, "scac_code");
  const blNumber = stringOf(s11, "bl_number");
  if (scacCode === null || blNumber === null || s10Container === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_CARRIER_CONSISTENCY_S10_S11",
      ["L4.S10_BOLT_SEAL", "L4.S11_BILL_OF_LADING"],
      "NOT_EVALUATED",
      "Carrier code, bill-of-lading number, or container number is unavailable."
    );
  } else {
    const prefixConsistent =
      blNumber.startsWith(scacCode) && s10Container.startsWith(scacCode);
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_CARRIER_CONSISTENCY_S10_S11",
      ["L4.S10_BOLT_SEAL", "L4.S11_BILL_OF_LADING"],
      prefixConsistent ? "PASS" : "FAIL",
      prefixConsistent
        ? `SCAC ${scacCode} is consistent with B/L ${blNumber} and container ${s10Container}.`
        : `Carrier mismatch: SCAC ${scacCode}, B/L ${blNumber}, container ${s10Container}.`,
      "ERR_SEMANTIC_CARRIER_MISMATCH"
    );
  }

  const cleanOnBoard = booleanOf(s11, "clean_on_board");
  addSemanticCheck(
    gate2Semantics,
    gate2HaltReasons,
    "G2_CLEAN_ON_BOARD_S11",
    ["L4.S11_BILL_OF_LADING"],
    cleanOnBoard === true ? "PASS" : "FAIL",
    cleanOnBoard === true
      ? "Bill of lading is marked clean on board under UCP 600 Art. 27."
      : "Bill of lading is not clean on board.",
    "ERR_SEMANTIC_BL_NOT_CLEAN"
  );

  const s04Country = stringOf(s04, "country_iso2");
  const s12Country = stringOf(s12, "country_of_origin_iso2");
  if (s04Country === null || s12Country === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_ORIGIN_S04_S12",
      ["L2.S04_SUPPLIER_KYB", "L4.S12_CERTIFICATE_OF_ORIGIN"],
      "NOT_EVALUATED",
      "Supplier country or certificate-of-origin country is unavailable."
    );
  } else {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_ORIGIN_S04_S12",
      ["L2.S04_SUPPLIER_KYB", "L4.S12_CERTIFICATE_OF_ORIGIN"],
      s04Country === s12Country ? "PASS" : "FAIL",
      s04Country === s12Country
        ? `Supplier country ${s04Country} agrees with the certificate of origin.`
        : `Origin mismatch: supplier country ${s04Country} versus certificate ${s12Country}.`,
      "ERR_SEMANTIC_ORIGIN_MISMATCH"
    );
  }

  const originCriterion = stringOf(s12, "origin_criterion");
  const tier2Origin = stringOf(s12, "tier2_yarn_origin_iso2");
  const tier3Origin = stringOf(s12, "tier3_raw_material_origin_iso2");
  if (originCriterion === "WO") {
    if (tier2Origin === null || tier3Origin === null) {
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_ORIGIN_CRITERION_S12",
        ["L4.S12_CERTIFICATE_OF_ORIGIN"],
        "NOT_EVALUATED",
        "Wholly-obtained criterion requires tier-2 and tier-3 input origins."
      );
    } else {
      const whollyObtained =
        tier2Origin === s12Country && tier3Origin === s12Country;
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_ORIGIN_CRITERION_S12",
        ["L4.S12_CERTIFICATE_OF_ORIGIN"],
        whollyObtained ? "PASS" : "FAIL",
        whollyObtained
          ? `Wholly-obtained criterion is consistent with domestic tier-2/tier-3 inputs (${tier2Origin}, ${tier3Origin}).`
          : `Origin criterion WO conflicts with imported inputs: tier-2 ${tier2Origin}, tier-3 ${tier3Origin}, origin ${s12Country}.`,
        "ERR_SEMANTIC_ORIGIN_CRITERION"
      );
    }
  } else if (originCriterion === "CC" || originCriterion === "CTH") {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_ORIGIN_CRITERION_S12",
      ["L4.S12_CERTIFICATE_OF_ORIGIN"],
      "PASS",
      `Origin criterion ${originCriterion} permits the declared imported tier-2/tier-3 inputs.`
    );
  } else {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_ORIGIN_CRITERION_S12",
      ["L4.S12_CERTIFICATE_OF_ORIGIN"],
      "NOT_EVALUATED",
      `Origin criterion ${originCriterion ?? "absent"} is not in the recognised set.`
    );
  }

  const proofType = stringOf(s12, "proof_type");
  const originRegime = stringOf(s12, "origin_regime");
  if (proofType === "REX_STATEMENT") {
    const regimeConsistent =
      originRegime === "PREFERENTIAL" && stringOf(s12, "exporter_rex_id") !== null;
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_ORIGIN_REGIME_S12",
      ["L4.S12_CERTIFICATE_OF_ORIGIN"],
      regimeConsistent ? "PASS" : "FAIL",
      regimeConsistent
        ? "REX statement is declared under the preferential origin regime."
        : "REX statement requires a preferential regime and an exporter REX identifier.",
      "ERR_SEMANTIC_ORIGIN_REGIME"
    );
  } else if (proofType === "CHAMBER_CERTIFICATE") {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_ORIGIN_REGIME_S12",
      ["L4.S12_CERTIFICATE_OF_ORIGIN"],
      originRegime === "NON_PREFERENTIAL" ? "PASS" : "FAIL",
      originRegime === "NON_PREFERENTIAL"
        ? "Chamber certificate is declared under the non-preferential regime."
        : "Chamber certificate must be declared under the non-preferential regime.",
      "ERR_SEMANTIC_ORIGIN_REGIME"
    );
  } else {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_ORIGIN_REGIME_S12",
      ["L4.S12_CERTIFICATE_OF_ORIGIN"],
      "NOT_EVALUATED",
      "Origin proof type is absent or not CHAMBER_CERTIFICATE/REX_STATEMENT."
    );
  }

  const s05Rex = stringOf(s05, "rex_number");
  const s12Rex = stringOf(s12, "exporter_rex_id");
  if (proofType !== "REX_STATEMENT") {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_REX_S05_S12",
      ["L2.S05_REGISTRY_STANDING", "L4.S12_CERTIFICATE_OF_ORIGIN"],
      "NOT_EVALUATED",
      "REX consistency applies only to a preferential REX statement on origin."
    );
  } else if (s05Rex === null || s12Rex === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_REX_S05_S12",
      ["L2.S05_REGISTRY_STANDING", "L4.S12_CERTIFICATE_OF_ORIGIN"],
      "NOT_EVALUATED",
      "REX identifier is unavailable in the registry or origin slot."
    );
  } else {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_REX_S05_S12",
      ["L2.S05_REGISTRY_STANDING", "L4.S12_CERTIFICATE_OF_ORIGIN"],
      s05Rex === s12Rex ? "PASS" : "FAIL",
      s05Rex === s12Rex
        ? `REX identifier ${s05Rex} is consistent across registry and REX statement.`
        : `REX mismatch: registry ${s05Rex} versus origin statement ${s12Rex}.`,
      "ERR_SEMANTIC_REX_MISMATCH"
    );
  }

  if (s14 === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_CIF_S14",
      ["L5.S14_LANDED_VALUATION"],
      "NOT_EVALUATED",
      "Landed valuation payload is unavailable."
    );
  } else {
    const fob = numberOf(s14, "fob_value_eur");
    const freight = numberOf(s14, "international_freight_eur");
    const insurance = numberOf(s14, "insurance_eur");
    const cif = numberOf(s14, "cif_customs_value_eur");
    if (fob === null || freight === null || insurance === null || cif === null) {
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_CIF_S14",
        ["L5.S14_LANDED_VALUATION"],
        "FAIL",
        "Landed valuation arithmetic inputs are incomplete.",
        "ERR_SEMANTIC_CIF_ARITHMETIC"
      );
    } else {
      const delta = Math.abs(fob + freight + insurance - cif);
      addSemanticCheck(
        gate2Semantics,
        gate2HaltReasons,
        "G2_CIF_S14",
        ["L5.S14_LANDED_VALUATION"],
        delta <= 0.01 ? "PASS" : "FAIL",
        `FOB ${fob.toFixed(2)} + freight ${freight.toFixed(2)} + insurance ${insurance.toFixed(2)} = ${(fob + freight + insurance).toFixed(2)} EUR versus declared CIF ${cif.toFixed(2)} EUR (tolerance 0.01 EUR).`,
        "ERR_SEMANTIC_CIF_ARITHMETIC"
      );
    }
  }

  const taric = stringOf(s15, "taric_10_code");
  if (s15 === null || taric === null) {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_TARIC_S15",
      ["L5.S15_DUTY_CALCULATION"],
      "NOT_EVALUATED",
      "10-digit TARIC code is unavailable."
    );
  } else {
    addSemanticCheck(
      gate2Semantics,
      gate2HaltReasons,
      "G2_TARIC_S15",
      ["L5.S15_DUTY_CALCULATION"],
      /^[0-9]{10}$/.test(taric) ? "PASS" : "FAIL",
      /^[0-9]{10}$/.test(taric)
        ? `TARIC code ${taric} is a valid 10-digit commodity code.`
        : `TARIC code ${taric} does not match ^[0-9]{10}$.`,
      "ERR_SEMANTIC_TARIC_FORMAT"
    );
  }

  const gate2SemanticsOk = gate2Semantics.every((check) => check.status !== "FAIL");
  const gate2: GateResult = {
    gate_id: "GATE_02_BALANCE_AND_PRE_CLEARANCE",
    verdict:
      gate2StateResult.uncorroborated.length === 0 && gate2SemanticsOk
        ? "READY"
        : "HARD_STOP",
    mandatory_slots: gate2Mandatory,
    uncorroborated_slots: gate2StateResult.uncorroborated,
    slot_states: gate2StateResult.states,
    halt_reasons: gate2HaltReasons,
    semantic_checks: gate2Semantics,
    semantics_ok: gate2SemanticsOk
  };

  const institutionalViews = buildInstitutionalViews(
    dossier,
    referenceTime,
    gate1,
    gate2,
    effectiveStates
  );

  return {
    dossier_id: dossier.dossier_id,
    tenant_id: dossier.tenant_id,
    reference_time: referenceTime,
    seal_verification: sealVerification,
    gates: {
      GATE_01_DEPOSIT_PRE_WIRE: gate1,
      GATE_02_BALANCE_AND_PRE_CLEARANCE: gate2
    },
    institutional_views: institutionalViews,
    blind_index: dossier.blind_index ?? null
  };
}

/** Number of hexadecimal characters in the pinned test fixture digests. */
export const DIGEST_HEX_LENGTH = HEX_32_BYTES;
export const SALT_HEX_LENGTH = HEX_16_BYTES;
export const IV_HEX_LENGTH = HEX_12_BYTES;
