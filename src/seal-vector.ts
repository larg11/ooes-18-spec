import crypto from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SLOT_LAYER,
  computeBlindIndex,
  computeDossierMerkleRoot,
  computeJcsSha256,
  computeSlotDigest,
  computeSlotDigestsMapHash,
  deriveSlotKey,
  encryptSlotPayload,
  evaluateReleaseGates,
  type AttestationMetadata,
  type AttesterType,
  type OOES18Dossier,
  type SlotEnvelope,
  type SlotId
} from "./verifier.js";

const MASTER_SECRET_HEX =
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const HKDF_SALT_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const NETWORK_REGISTRY_SALT_HEX =
  "f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";

const DOSSIER_ID = "CASCADE-2026-9F4A2C";
const TENANT_ID = "TENANT-FR-IMPORT-75008";

const CREATED_AT = "2026-10-20T08:00:00Z";
const REFERENCE_TIME = "2026-10-20T12:00:00Z";
const SEALED_AT = "2026-10-20T10:00:00Z";
const ATTESTED_AT = "2026-10-19T09:30:00Z";
const ATTESTATION_EXPIRES_AT = "2027-12-31T23:59:59Z";

const BL_NUMBER = "MAEU260984112";
const CONTAINER_NUMBER = "MSCU5829104";
const SUPPLIER_TAX_ID = "BD-BIN-004918273-0101";
const INVOICE_DATE = "2026-10-12";

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function ivFor(slotId: string): string {
  return sha256Hex(`OOES-18-IV|v1|${DOSSIER_ID}|${slotId}`).slice(0, 24);
}

interface AttesterSpec {
  type: AttesterType;
  authority: string;
  accreditationId: string | null;
}

function makeAttestation(slotKey: Buffer, spec: AttesterSpec): AttestationMetadata {
  const unsigned = {
    attester_type: spec.type,
    authority_name: spec.authority,
    accreditation_id: spec.accreditationId,
    attested_at: ATTESTED_AT,
    expires_at: ATTESTATION_EXPIRES_AT
  };
  const signature_hex = computeSlotDigest(slotKey, unsigned);
  return { ...unsigned, signature_hex };
}

function sealedSlot(
  slotId: SlotId,
  state: "ASSERTED" | "CORROBORATED",
  payload: Record<string, unknown>,
  attester: AttesterSpec
): SlotEnvelope {
  const slotKey = deriveSlotKey(MASTER_SECRET_HEX, HKDF_SALT_HEX, TENANT_ID, DOSSIER_ID, slotId);
  const jcs_sha256 = computeJcsSha256(payload);
  const hmac_sha256 = computeSlotDigest(slotKey, payload);
  const aes_gcm_iv = ivFor(slotId);
  const encrypted = encryptSlotPayload(
    slotKey,
    aes_gcm_iv,
    DOSSIER_ID,
    slotId,
    state,
    payload
  );
  const attestation = makeAttestation(slotKey, attester);

  return {
    slot_id: slotId,
    layer: SLOT_LAYER[slotId],
    state,
    payload,
    seal: {
      hkdf_salt: HKDF_SALT_HEX,
      jcs_sha256,
      hmac_sha256,
      aes_gcm_iv,
      aes_gcm_ciphertext: encrypted.ciphertextHex,
      aes_gcm_tag: encrypted.authTagHex,
      sealed_at: SEALED_AT
    },
    attestation,
    fault_codes: []
  };
}

function unknownSlot(slotId: SlotId): SlotEnvelope {
  return {
    slot_id: slotId,
    layer: SLOT_LAYER[slotId],
    state: "UNKNOWN",
    payload: null,
    seal: null,
    attestation: null,
    fault_codes: []
  };
}

const AUTHORITY_SOVEREIGN = (authority: string, accreditationId: string): AttesterSpec => ({
  type: "SOVEREIGN_AUTHORITY",
  authority,
  accreditationId
});

const THIRD_PARTY = (authority: string, accreditationId: string): AttesterSpec => ({
  type: "ACCREDITED_THIRD_PARTY",
  authority,
  accreditationId
});

const SELF_DECLARED: AttesterSpec = {
  type: "PARTY_SELF_DECLARATION",
  authority: "Exporter self-declaration (signature verified at upload)",
  accreditationId: null
};

const purchaseOrder = {
  po_number: "PO-LEH-2026-10-004418",
  buyer_eori: "FR75080234560018",
  supplier_id: "SUP-BD-GAZIPUR-4419",
  incoterms_2020: "FOB",
  currency: "EUR",
  total_amount: 144000,
  total_units: 12000,
  unit_price: 12,
  delivery_window_end: "2026-12-05"
};

const techPack = {
  tech_pack_id: "TP-WWJ-290-2026-07",
  sku_code: "WWJ-290-BLK-001",
  product_description: "Men's 100% heavy cotton twill workwear jacket, black, 290 GSM",
  fiber_composition: "100% Cotton",
  gsm_weight: 290,
  dimensional_tolerance_pct: 3.0,
  bom_hash: sha256Hex("OOES-18|BOM|WWJ-290-BLK-001|v2026-07")
};

const goldenSample = {
  sample_seal_tag: "GS-BD-4419-2026-0918",
  physical_sha256_manifest: sha256Hex("OOES-18|GOLDEN-SAMPLE|GS-BD-4419-2026-0918"),
  approved_by_buyer_id: "BUYER-FR-75008",
  approved_at: "2026-09-18T14:20:00Z",
  colorfastness_baseline: "4-5"
};

const supplierKyb = {
  legal_name: "Dhaka Apparels & Workwear Ltd.",
  tax_registration_id: SUPPLIER_TAX_ID,
  country_iso2: "BD",
  factory_lat: 23.9999,
  factory_lon: 90.4203,
  beneficial_owners_verified: true
};

const registryStanding = {
  registry_authority: "BGMEA",
  membership_id: "BGMEA-4419",
  rex_number: "BDREX882190",
  eu_2024_3015_screening_status: "CLEAR",
  sanctions_clear: true
};

const capacityAttestation = {
  allocated_lines: 4,
  daily_output_capacity_units: 850,
  subcontracting_authorized: false,
  tier2_mill_tax_ids: ["BD-BIN-009127364-0202", "BD-BIN-007731095-0303"]
};

const productionPhotos = {
  media_count: 42,
  capture_device_pubkey_fp: sha256Hex("OOES-18|DEVICE|SGS-BD-CAM-0042"),
  exif_gps_lat: 24.0005,
  exif_gps_lon: 90.4208,
  max_distance_from_s04_meters: 82.4,
  merkle_media_root: sha256Hex("OOES-18|MEDIA-MERKLE|CASCADE-2026-9F4A2C|42")
};

const inlineAql = {
  inspector_agency: "SGS Bangladesh Ltd",
  iso17020_accreditation_id: "SGS-17020-BD-0042",
  aql_standard: "ISO_2859_1_AQL_2_5",
  sample_size: 315,
  critical_defects: 0,
  major_defects: 4,
  max_allowed_major: 14,
  result: "PASS"
};

const labCertificate = {
  lab_name: "Bureau Veritas CPS Dhaka",
  iso17025_accreditation_id: "BV-ISO17025-BD-0427",
  report_number: "BV-CPS-2026-10-88419",
  reach_annex_xvii_compliant: true,
  azo_dyes_ppm: 4.2,
  measured_cotton_pct: 99.4,
  espr_dpp_uid: "DPP-BD-6203321000-2026-0004419"
};

const boltSeal = {
  seal_serial_number: "SL-BD-994812",
  iso17712_clause_6_compliant: true,
  container_number: CONTAINER_NUMBER,
  stuffing_lat: 22.3053,
  stuffing_lon: 91.8002,
  sealed_at: "2026-10-17T16:40:00Z"
};

const billOfLading = {
  bl_number: BL_NUMBER,
  scac_code: "MAEU",
  vessel_name: "MSC ISABELLA",
  vessel_imo: "9776432",
  port_of_loading_unlocode: "BDCGP",
  port_of_discharge_unlocode: "FRLEH",
  container_number: CONTAINER_NUMBER,
  shipped_on_board_date: "2026-10-18",
  gross_weight_kg: 6480,
  carton_count: 480,
  clean_on_board: true
};

const certificateOfOrigin = {
  coo_number: "COO-BD-2026-88419",
  issuing_authority: "Chittagong Chamber of Commerce & Industry",
  origin_criterion: "WO",
  country_of_origin_iso2: "BD",
  exporter_rex_id: "BDREX882190",
  tier2_yarn_origin_iso2: "IN",
  tier3_raw_material_origin_iso2: "US"
};

const slots: Record<string, SlotEnvelope> = {
  "L1.S01_PURCHASE_ORDER": sealedSlot(
    "L1.S01_PURCHASE_ORDER",
    "CORROBORATED",
    purchaseOrder,
    AUTHORITY_SOVEREIGN("DGFiP Chorus Pro (France)", "FR-CHORUS-PRO-REG-75008")
  ),
  "L1.S02_TECH_PACK": sealedSlot(
    "L1.S02_TECH_PACK",
    "CORROBORATED",
    techPack,
    THIRD_PARTY("QIMA Limited", "QIMA-ISO17020-2026-1188")
  ),
  "L1.S03_GOLDEN_SAMPLE": sealedSlot(
    "L1.S03_GOLDEN_SAMPLE",
    "CORROBORATED",
    goldenSample,
    THIRD_PARTY("SGS Bangladesh Ltd", "SGS-17020-BD-0042")
  ),
  "L2.S04_SUPPLIER_KYB": sealedSlot(
    "L2.S04_SUPPLIER_KYB",
    "CORROBORATED",
    supplierKyb,
    AUTHORITY_SOVEREIGN("Bangladesh RJSC / NBR", "BD-RJSC-REG-4419")
  ),
  "L2.S05_REGISTRY_STANDING": sealedSlot(
    "L2.S05_REGISTRY_STANDING",
    "ASSERTED",
    registryStanding,
    SELF_DECLARED
  ),
  "L2.S06_CAPACITY_ATTESTATION": sealedSlot(
    "L2.S06_CAPACITY_ATTESTATION",
    "ASSERTED",
    capacityAttestation,
    SELF_DECLARED
  ),
  "L3.S07_PRODUCTION_PHOTOS": sealedSlot(
    "L3.S07_PRODUCTION_PHOTOS",
    "CORROBORATED",
    productionPhotos,
    THIRD_PARTY("SGS Bangladesh Ltd", "SGS-17020-BD-0042")
  ),
  "L3.S08_INLINE_AQL": sealedSlot(
    "L3.S08_INLINE_AQL",
    "CORROBORATED",
    inlineAql,
    THIRD_PARTY("SGS Bangladesh Ltd", "SGS-17020-BD-0042")
  ),
  "L3.S09_LAB_CERTIFICATE": sealedSlot(
    "L3.S09_LAB_CERTIFICATE",
    "CORROBORATED",
    labCertificate,
    THIRD_PARTY("Bureau Veritas CPS Dhaka", "BV-ISO17025-BD-0427")
  ),
  "L4.S10_BOLT_SEAL": sealedSlot(
    "L4.S10_BOLT_SEAL",
    "CORROBORATED",
    boltSeal,
    THIRD_PARTY("SGS Bangladesh Ltd", "SGS-ISO17712-BD-0042")
  ),
  "L4.S11_BILL_OF_LADING": sealedSlot(
    "L4.S11_BILL_OF_LADING",
    "ASSERTED",
    billOfLading,
    SELF_DECLARED
  ),
  "L4.S12_CERTIFICATE_OF_ORIGIN": sealedSlot(
    "L4.S12_CERTIFICATE_OF_ORIGIN",
    "ASSERTED",
    certificateOfOrigin,
    SELF_DECLARED
  ),
  "L4.S13_SETTLEMENT_INSTRUMENT": unknownSlot("L4.S13_SETTLEMENT_INSTRUMENT"),
  "L5.S14_LANDED_VALUATION": unknownSlot("L5.S14_LANDED_VALUATION"),
  "L5.S15_DUTY_CALCULATION": unknownSlot("L5.S15_DUTY_CALCULATION"),
  "L5.S16_PSI_REPORT": unknownSlot("L5.S16_PSI_REPORT"),
  "L5.S17_GPS_TELEMETRY": unknownSlot("L5.S17_GPS_TELEMETRY"),
  "L5.S18_AUDIT_SIGNATURE": unknownSlot("L5.S18_AUDIT_SIGNATURE")
};

const blindIndex = computeBlindIndex(
  NETWORK_REGISTRY_SALT_HEX,
  BL_NUMBER,
  CONTAINER_NUMBER,
  SUPPLIER_TAX_ID,
  INVOICE_DATE
);

const dossier: OOES18Dossier = {
  standard: "OOES-18",
  version: "1.0.0",
  dossier_id: DOSSIER_ID,
  tenant_id: TENANT_ID,
  created_at: CREATED_AT,
  reference_time: REFERENCE_TIME,
  hkdf_salt_hex: HKDF_SALT_HEX,
  slots,
  blind_index: {
    normalized_tuple: blindIndex.normalizedTuple,
    blind_index_hex: blindIndex.blindIndexHex,
    registry_salt_id: "OOES-18-NETWORK-REGISTRY-2026-Q4"
  },
  dossier_state_root: computeDossierMerkleRoot(slots),
  slot_digests_map_hash: computeSlotDigestsMapHash(slots)
};

const evaluation = evaluateReleaseGates(dossier, MASTER_SECRET_HEX);
dossier.institutional_views = evaluation.institutional_views;

const counts = {
  CORROBORATED: Object.values(slots).filter((slot) => slot.state === "CORROBORATED").length,
  ASSERTED: Object.values(slots).filter((slot) => slot.state === "ASSERTED").length,
  UNKNOWN: Object.values(slots).filter((slot) => slot.state === "UNKNOWN").length
};

if (counts.CORROBORATED !== 8 || counts.ASSERTED !== 4 || counts.UNKNOWN !== 6) {
  throw new Error(
    `unexpected epistemic distribution: ${JSON.stringify(counts)}; expected 8/4/6`
  );
}

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, "../..");
const outputPath = resolve(repositoryRoot, "vectors", "CASCADE-2026-9F4A2C.dossier.json");
mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(dossier, null, 2)}\n`, "utf8");

console.log("OOES-18 deterministic test vector");
console.log(`  output           : ${outputPath}`);
console.log(`  dossier_id       : ${dossier.dossier_id}`);
console.log(`  slot states      : 8 CORROBORATED / 4 ASSERTED / 6 UNKNOWN`);
console.log(`  state root       : ${dossier.dossier_state_root}`);
console.log(`  blind index      : ${dossier.blind_index.blind_index_hex}`);
console.log(
  `  normalized tuple : ${dossier.blind_index.normalized_tuple}`
);
console.log(
  `  gate 01          : ${evaluation.gates.GATE_01_DEPOSIT_PRE_WIRE.verdict} (${evaluation.gates.GATE_01_DEPOSIT_PRE_WIRE.uncorroborated_slots.join(", ")})`
);
console.log(
  `  gate 02          : ${evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE.verdict} (${evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE.uncorroborated_slots.join(", ")})`
);
console.log(`  seal verification: ${evaluation.seal_verification.ok ? "ALL SEALS VALID" : "FAILED"}`);
