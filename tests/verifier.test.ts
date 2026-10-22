import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  computeBlindIndex,
  computeDossierMerkleRoot,
  computeJcsSha256,
  computeSlotDigest,
  deriveSlotKey,
  encryptSlotPayload,
  evaluateReleaseGates,
  verifyDossierSeals,
  canonicalizeJCS,
  type AttestationMetadata,
  type AttesterType,
  type EpistemicState,
  type OOES18Dossier,
  type SlotId
} from "../src/verifier.js";

const MASTER_SECRET_HEX =
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const HKDF_SALT_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const NETWORK_REGISTRY_SALT_HEX =
  "f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";

const VECTOR_PATH = resolve(process.cwd(), "vectors", "CASCADE-2026-9F4A2C.dossier.json");

const S01 = "L1.S01_PURCHASE_ORDER";
const S02 = "L1.S02_TECH_PACK";
const S04 = "L2.S04_SUPPLIER_KYB";
const S05 = "L2.S05_REGISTRY_STANDING";
const S06 = "L2.S06_CAPACITY_ATTESTATION";
const S07 = "L3.S07_PRODUCTION_PHOTOS";
const S08 = "L3.S08_INLINE_AQL";
const S09 = "L3.S09_LAB_CERTIFICATE";
const S10 = "L4.S10_BOLT_SEAL";
const S11 = "L4.S11_BILL_OF_LADING";
const S12 = "L4.S12_CERTIFICATE_OF_ORIGIN";
const S14 = "L5.S14_LANDED_VALUATION";
const S15 = "L5.S15_DUTY_CALCULATION";

function loadVector(): OOES18Dossier {
  return JSON.parse(readFileSync(VECTOR_PATH, "utf8")) as OOES18Dossier;
}

function cloneVector(): OOES18Dossier {
  return structuredClone(loadVector());
}

function attestationSpec(
  type: AttesterType,
  authority: string,
  accreditationId: string | null
): { type: AttesterType; authority: string; accreditationId: string | null } {
  return { type, authority, accreditationId };
}

function resealSlot(
  dossier: OOES18Dossier,
  slotId: SlotId,
  state: EpistemicState,
  payload: Record<string, unknown>,
  attester: { type: AttesterType; authority: string; accreditationId: string | null }
): void {
  const slotKey = deriveSlotKey(
    MASTER_SECRET_HEX,
    dossier.hkdf_salt_hex,
    dossier.tenant_id,
    dossier.dossier_id,
    slotId
  );
  const jcsSha = computeJcsSha256(payload);
  const hmac = computeSlotDigest(slotKey, payload);
  const iv = crypto
    .createHash("sha256")
    .update(`OOES-18-TEST-IV|${dossier.dossier_id}|${slotId}|${jcsSha}`, "utf8")
    .digest("hex")
    .slice(0, 24);
  const encrypted = encryptSlotPayload(slotKey, iv, dossier.dossier_id, slotId, state, payload);

  const unsignedAttestation = {
    attester_type: attester.type,
    authority_name: attester.authority,
    accreditation_id: attester.accreditationId,
    attested_at: "2026-10-20T09:00:00Z",
    expires_at: "2027-12-31T23:59:59Z"
  };
  const attestation: AttestationMetadata = {
    ...unsignedAttestation,
    signature_hex: computeSlotDigest(slotKey, unsignedAttestation)
  };

  dossier.slots[slotId] = {
    slot_id: slotId,
    layer: dossier.slots[slotId]?.layer ?? "L1",
    state,
    payload,
    seal: {
      hkdf_salt: dossier.hkdf_salt_hex,
      jcs_sha256: jcsSha,
      hmac_sha256: hmac,
      aes_gcm_iv: iv,
      aes_gcm_ciphertext: encrypted.ciphertextHex,
      aes_gcm_tag: encrypted.authTagHex,
      sealed_at: "2026-10-20T09:00:00Z"
    },
    attestation,
    fault_codes: []
  };
}

function finalizeDossier(dossier: OOES18Dossier): void {
  dossier.dossier_state_root = computeDossierMerkleRoot(dossier.slots);
}

function buildReadyDossier(): OOES18Dossier {
  const dossier = cloneVector();
  const existing = (slotId: string): Record<string, unknown> => {
    const payload = dossier.slots[slotId]?.payload;
    if (!payload) {
      throw new Error(`missing payload for ${slotId}`);
    }
    return structuredClone(payload);
  };

  resealSlot(
    dossier,
    S05 as SlotId,
    "CORROBORATED",
    existing(S05),
    attestationSpec("SOVEREIGN_AUTHORITY", "BGMEA REX Registry API", "BD-REX-API-882190")
  );
  resealSlot(
    dossier,
    S06 as SlotId,
    "CORROBORATED",
    existing(S06),
    attestationSpec("ACCREDITED_THIRD_PARTY", "QIMA Limited", "QIMA-ISO17020-2026-1188")
  );
  resealSlot(
    dossier,
    S11 as SlotId,
    "CORROBORATED",
    existing(S11),
    attestationSpec("CARRIER_REGISTRY", "Maersk eBL Registry", "MAEU-EBL-REG-2026")
  );
  resealSlot(
    dossier,
    S12 as SlotId,
    "CORROBORATED",
    existing(S12),
    attestationSpec("SOVEREIGN_AUTHORITY", "Chittagong Chamber / REX Portal", "BD-REX-PORTAL-2026")
  );
  resealSlot(
    dossier,
    S14 as SlotId,
    "CORROBORATED",
    {
      invoice_number: "INV-LEH-2026-10-88419",
      invoice_date: "2026-10-12",
      fob_value_eur: 144000,
      international_freight_eur: 4200,
      insurance_eur: 300,
      cif_customs_value_eur: 148500,
      valuation_method: "UCC_ART_70_TRANSACTION_VALUE"
    },
    attestationSpec("SOVEREIGN_AUTHORITY", "French Customs Valuation API", "FR-DOUANE-VAL-2026")
  );
  resealSlot(
    dossier,
    S15 as SlotId,
    "CORROBORATED",
    {
      taric_10_code: "6203321000",
      preference_code: "200",
      mfn_duty_rate_pct: 12,
      preferential_duty_rate_pct: 0,
      calculated_duty_eur: 0,
      import_vat_rate_pct: 20,
      calculated_vat_eur: 29700
    },
    attestationSpec("SOVEREIGN_AUTHORITY", "French Customs TARIC API", "FR-DOUANE-TARIC-2026")
  );

  finalizeDossier(dossier);
  return dossier;
}

function gate2AfterMutation(mutator: (dossier: OOES18Dossier) => void): {
  verdict: string;
  codes: string[];
  uncorroborated: string[];
  sealsOk: boolean;
} {
  const dossier = buildReadyDossier();
  mutator(dossier);
  finalizeDossier(dossier);
  const evaluation = evaluateReleaseGates(dossier, MASTER_SECRET_HEX);
  const gate2 = evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE;
  return {
    verdict: gate2.verdict,
    codes: gate2.halt_reasons.map((reason) => reason.code),
    uncorroborated: gate2.uncorroborated_slots,
    sealsOk: evaluation.seal_verification.ok
  };
}

test("1. RFC 8785 JCS canonicalization is order-invariant and ECMA-262 exact", () => {
  assert.equal(canonicalizeJCS({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalizeJCS({ a: 2, b: 1 }), '{"a":2,"b":1}');
  assert.equal(
    canonicalizeJCS({ b: 2, a: [{ d: 4, c: 3 }, null, true, "x"] }),
    '{"a":[{"c":3,"d":4},null,true,"x"],"b":2}'
  );
  assert.equal(canonicalizeJCS("é\u0001"), '"é\\u0001"');
  assert.equal(canonicalizeJCS(1e21), "1e+21");
  assert.equal(canonicalizeJCS(0.000001), "0.000001");
  assert.equal(canonicalizeJCS(1e-7), "1e-7");
  assert.equal(canonicalizeJCS(-0), "0");
  assert.equal(canonicalizeJCS(null), "null");
  assert.throws(() => canonicalizeJCS(Number.NaN), TypeError);
  assert.throws(() => canonicalizeJCS(Number.POSITIVE_INFINITY), TypeError);
  assert.throws(() => canonicalizeJCS({ x: undefined }), TypeError);
  assert.throws(() => canonicalizeJCS(new Date()), TypeError);

  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalizeJCS(cyclic), TypeError);

  const hashA = computeJcsSha256({ b: 1, a: 2 });
  const hashB = computeJcsSha256({ a: 2, b: 1 });
  assert.equal(hashA, hashB);
  assert.match(hashA, /^[0-9a-f]{64}$/);
});

test("2. HKDF-SHA256 domain separation isolates tenant, dossier, and slot keys", () => {
  const baseline = deriveSlotKey(
    MASTER_SECRET_HEX,
    HKDF_SALT_HEX,
    "TENANT-FR-IMPORT-75008",
    "CASCADE-2026-9F4A2C",
    S01
  );
  assert.equal(baseline.length, 32);

  const variants = [
    deriveSlotKey(
      MASTER_SECRET_HEX,
      HKDF_SALT_HEX,
      "TENANT-FR-IMPORT-75009",
      "CASCADE-2026-9F4A2C",
      S01
    ),
    deriveSlotKey(
      MASTER_SECRET_HEX,
      HKDF_SALT_HEX,
      "TENANT-FR-IMPORT-75008",
      "CASCADE-2026-9F4A2B",
      S01
    ),
    deriveSlotKey(
      MASTER_SECRET_HEX,
      HKDF_SALT_HEX,
      "TENANT-FR-IMPORT-75008",
      "CASCADE-2026-9F4A2C",
      S02
    )
  ];

  const baselineHex = baseline.toString("hex");
  for (const variant of variants) {
    assert.equal(variant.length, 32);
    assert.notEqual(variant.toString("hex"), baselineHex);
  }

  const unique = new Set([baselineHex, ...variants.map((key) => key.toString("hex"))]);
  assert.equal(unique.size, 4);
});

test("3. CASCADE-2026-9F4A2C authentic vector passes all seal checks", () => {
  const dossier = loadVector();
  const report = verifyDossierSeals(dossier, MASTER_SECRET_HEX);

  assert.equal(report.ok, true, JSON.stringify(report.errors));
  assert.equal(report.all_seals_valid, true);
  assert.equal(report.slots.length, 18);
  assert.equal(report.slots.filter((slot) => slot.fault_codes.length > 0).length, 0);
  assert.equal(
    report.slots.filter((slot) => slot.effective_state === "CORROBORATED").length,
    8
  );
  assert.equal(report.slots.filter((slot) => slot.effective_state === "ASSERTED").length, 4);
  assert.equal(report.slots.filter((slot) => slot.effective_state === "UNKNOWN").length, 6);
  assert.equal(computeDossierMerkleRoot(dossier.slots), dossier.dossier_state_root);
});

test("4. Default vector deterministically HARD_STOPs both gates with exact slot sets", () => {
  const evaluation = evaluateReleaseGates(loadVector(), MASTER_SECRET_HEX);
  const gate1 = evaluation.gates.GATE_01_DEPOSIT_PRE_WIRE;
  const gate2 = evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE;

  assert.equal(gate1.verdict, "HARD_STOP");
  assert.deepEqual(gate1.uncorroborated_slots, [S05, S06]);
  assert.ok(gate1.halt_reasons.some((reason) => reason.code === "ERR_SLOT_ASSERTED"));

  assert.equal(gate2.verdict, "HARD_STOP");
  assert.deepEqual(gate2.uncorroborated_slots, [S11, S12, S14, S15]);
  assert.ok(gate2.halt_reasons.some((reason) => reason.code === "ERR_SLOT_ASSERTED"));
  assert.ok(gate2.halt_reasons.some((reason) => reason.code === "ERR_SLOT_UNKNOWN"));

  assert.equal(evaluation.institutional_views.pre_wire_gate.verdict, "HARD_STOP");
  assert.equal(evaluation.institutional_views.delta_ie_h1_pack.overall, "INCOMPLETE");
});

test("5. Full corroboration promotion drives GATE_01 and GATE_02 to READY", () => {
  const dossier = buildReadyDossier();
  const evaluation = evaluateReleaseGates(dossier, MASTER_SECRET_HEX);

  assert.equal(evaluation.seal_verification.ok, true, JSON.stringify(evaluation.seal_verification.errors));
  assert.equal(evaluation.gates.GATE_01_DEPOSIT_PRE_WIRE.verdict, "READY");
  assert.equal(
    evaluation.gates.GATE_01_DEPOSIT_PRE_WIRE.uncorroborated_slots.length,
    0
  );
  assert.equal(evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE.verdict, "READY");
  assert.equal(
    evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE.uncorroborated_slots.length,
    0
  );
  assert.equal(
    evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE.semantics_ok,
    true
  );
  assert.equal(evaluation.institutional_views.pre_wire_gate.verdict, "READY");
});

test("6a. Container discontinuity rejects a fully corroborated dossier", () => {
  const result = gate2AfterMutation((dossier) => {
    const payload = dossier.slots[S11]?.payload;
    assert.ok(payload);
    payload.container_number = "TGHU7654321";
    resealSlot(
      dossier,
      S11 as SlotId,
      "CORROBORATED",
      payload,
      attestationSpec("CARRIER_REGISTRY", "Maersk eBL Registry", "MAEU-EBL-REG-2026")
    );
  });

  assert.equal(result.sealsOk, true);
  assert.deepEqual(result.uncorroborated, []);
  assert.equal(result.verdict, "HARD_STOP");
  assert.ok(result.codes.includes("ERR_SEMANTIC_CONTAINER_MISMATCH"));
});

test("6b. Geofence violation rejects a fully corroborated dossier", () => {
  const result = gate2AfterMutation((dossier) => {
    const payload = dossier.slots[S07]?.payload;
    assert.ok(payload);
    payload.exif_gps_lat = 24.0505;
    payload.exif_gps_lon = 90.4708;
    resealSlot(
      dossier,
      S07 as SlotId,
      "CORROBORATED",
      payload,
      attestationSpec("ACCREDITED_THIRD_PARTY", "SGS Bangladesh Ltd", "SGS-17020-BD-0042")
    );
  });

  assert.equal(result.sealsOk, true);
  assert.deepEqual(result.uncorroborated, []);
  assert.equal(result.verdict, "HARD_STOP");
  assert.ok(result.codes.includes("ERR_SEMANTIC_GEOFENCE_DISTANCE"));
});

test("6c. CIF arithmetic error rejects a fully corroborated dossier", () => {
  const result = gate2AfterMutation((dossier) => {
    const payload = dossier.slots[S14]?.payload;
    assert.ok(payload);
    payload.cif_customs_value_eur = 148600;
    resealSlot(
      dossier,
      S14 as SlotId,
      "CORROBORATED",
      payload,
      attestationSpec("SOVEREIGN_AUTHORITY", "French Customs Valuation API", "FR-DOUANE-VAL-2026")
    );
  });

  assert.equal(result.sealsOk, true);
  assert.deepEqual(result.uncorroborated, []);
  assert.equal(result.verdict, "HARD_STOP");
  assert.ok(result.codes.includes("ERR_SEMANTIC_CIF_ARITHMETIC"));
});

test("7. Salted blind index collides across two banks despite formatting mutation", () => {
  const bankA = computeBlindIndex(
    NETWORK_REGISTRY_SALT_HEX,
    "MAEU260984112",
    " mscu-582910-4 ",
    "bd-bin-004918273-0101",
    "2026-10-12"
  );
  const bankB = computeBlindIndex(
    NETWORK_REGISTRY_SALT_HEX,
    " maeu260984112 ",
    "MSCU5829104",
    "BDBIN0049182730101",
    "2026-10-12"
  );

  assert.equal(bankA.normalizedTuple, "MAEU260984112|MSCU5829104|BDBIN0049182730101|2026-10-12");
  assert.equal(bankA.normalizedTuple, bankB.normalizedTuple);
  assert.equal(bankA.blindIndexHex, bankB.blindIndexHex);
  assert.match(bankA.blindIndexHex, /^[0-9a-f]{64}$/);
  assert.equal(bankA.blindIndexHex, loadVector().blind_index.blind_index_hex);

  const otherRegistry = computeBlindIndex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "MAEU260984112",
    "MSCU5829104",
    "BDBIN0049182730101",
    "2026-10-12"
  );
  assert.notEqual(otherRegistry.blindIndexHex, bankA.blindIndexHex);
});

test("8. Single-byte tamper of L3.S09 is demoted and halts GATE_02", () => {
  const dossier = loadVector();
  const labPayload = dossier.slots[S09]?.payload;
  assert.ok(labPayload);
  assert.equal(labPayload.measured_cotton_pct, 99.4);
  labPayload.measured_cotton_pct = 99.5;

  const evaluation = evaluateReleaseGates(dossier, MASTER_SECRET_HEX);
  const forged = evaluation.seal_verification.slots.find((slot) => slot.slot_id === S09);
  assert.ok(forged);

  assert.equal(evaluation.seal_verification.ok, false);
  assert.equal(forged.declared_state, "CORROBORATED");
  assert.equal(forged.effective_state, "UNKNOWN");
  assert.equal(forged.jcs_sha256_match, false);
  assert.equal(forged.hmac_sha256_match, false);
  assert.equal(forged.aes_gcm_authenticated, false);
  assert.ok(forged.fault_codes.includes("ERR_SEAL_INTEGRITY_FAILURE"));
  assert.ok(forged.fault_codes.includes("ERR_AES_GCM_AUTH_FAILURE"));

  const gate2 = evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE;
  assert.equal(gate2.verdict, "HARD_STOP");
  assert.ok(gate2.uncorroborated_slots.includes(S09));
  assert.ok(gate2.halt_reasons.some((reason) => reason.code === "ERR_SEAL_INTEGRITY_FAILURE"));
});

test("9. Gate equations are deterministic across repeated evaluation", () => {
  const dossier = loadVector();
  const first = evaluateReleaseGates(dossier, MASTER_SECRET_HEX);
  const second = evaluateReleaseGates(dossier, MASTER_SECRET_HEX);
  assert.deepEqual(first.gates, second.gates);
  assert.deepEqual(first.seal_verification, second.seal_verification);
  assert.equal(first.institutional_views.pre_wire_gate.verdict, "HARD_STOP");
  assert.equal(first.institutional_views.lc_mt700_check.overall, "INCOMPLETE");
});
