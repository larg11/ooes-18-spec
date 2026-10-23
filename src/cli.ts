import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  computeJcsSha256,
  evaluateReleaseGates,
  isTrustedAttester,
  verifyAttestationSignature,
  type AttesterTrustStore,
  type GateEvaluationReport,
  type GateResult,
  type OOES18Dossier,
  type SealVerificationReport,
  type SlotSealReport
} from "./verifier.js";

const MASTER_SECRET_HEX =
  process.env.OOES18_MASTER_SECRET ??
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

const VECTOR_PATH = resolve(process.cwd(), "vectors", "CASCADE-2026-9F4A2C.dossier.json");
const TRUST_PATH = resolve(process.cwd(), "trust", "attesters.json");

function loadDossier(): OOES18Dossier {
  return JSON.parse(readFileSync(VECTOR_PATH, "utf8")) as OOES18Dossier;
}

function loadTrustStore(): AttesterTrustStore {
  return JSON.parse(readFileSync(TRUST_PATH, "utf8")) as AttesterTrustStore;
}

function pad(value: string, width: number): string {
  return value.length >= width ? value.slice(0, width) : value.padEnd(width, " ");
}

function hexCell(match: boolean, available: boolean): string {
  if (!available) {
    return "n/a";
  }
  return match ? "MATCH" : "MISMATCH";
}

function printSlotTable(report: SealVerificationReport): void {
  const separator = `+----+------------------------------+-------+--------------+--------------+-----------+-----------+-----------+`;
  console.log("SLOT FORENSIC TABLE (18 SLOTS)");
  console.log(separator);
  console.log(
    `| #  | Slot ID                      | Layer | Declared     | Effective    | JCS SHA   | HMAC      | AES-GCM   |`
  );
  console.log(separator);

  report.slots.forEach((slot: SlotSealReport, index: number) => {
    const hasPayload =
      slot.declared_state !== "UNKNOWN" || slot.jcs_sha256_match || slot.hmac_sha256_match;
    console.log(
      `| ${pad(String(index + 1), 2)} | ${pad(slot.slot_id, 28)} | ${pad(slot.layer, 5)} | ${pad(
        slot.declared_state,
        12
      )} | ${pad(slot.effective_state, 12)} | ${pad(
        hexCell(slot.jcs_sha256_match, hasPayload),
        9
      )} | ${pad(hexCell(slot.hmac_sha256_match, hasPayload), 9)} | ${pad(
        slot.aes_gcm_authenticated ? "VALID" : hasPayload ? "INVALID" : "n/a",
        9
      )} |`
    );
  });
  console.log(separator);

  const corroborated = report.slots.filter(
    (slot) => slot.declared_state === "CORROBORATED"
  );
  const trusted = corroborated.filter((slot) => slot.attestation_trusted);
  console.log(
    `ATTESTATION TRUST: ${trusted.length}/${corroborated.length} CORROBORATED slots have a trusted Ed25519 attestation`
  );

  const faulted = report.slots.filter((slot) => slot.fault_codes.length > 0);
  if (faulted.length > 0) {
    console.log("FAULT CODES");
    for (const slot of faulted) {
      console.log(`  ${slot.slot_id}: ${slot.fault_codes.join(", ")}`);
    }
  } else {
    console.log("FAULT CODES: none");
  }
}

function printGate(gate: GateResult): void {
  const corroborated = gate.mandatory_slots.length - gate.uncorroborated_slots.length;
  console.log("");
  console.log(`${gate.gate_id}`);
  console.log(`  verdict         : ${gate.verdict}`);
  console.log(`  mandatory slots : ${gate.mandatory_slots.length}`);
  console.log(`  corroborated    : ${corroborated}/${gate.mandatory_slots.length}`);
  console.log(
    `  uncorroborated  : ${
      gate.uncorroborated_slots.length > 0
        ? gate.uncorroborated_slots
            .map((slotId) => `${slotId} (${gate.slot_states[slotId] ?? "UNKNOWN"})`)
            .join(", ")
        : "none"
    }`
  );
  if (gate.halt_reasons.length > 0) {
    console.log("  halt reasons    :");
    for (const reason of gate.halt_reasons) {
      console.log(
        `    - ${reason.code}${reason.slot_id ? ` [${reason.slot_id}]` : ""}: ${reason.detail}`
      );
    }
  } else {
    console.log("  halt reasons    : none");
  }
  console.log("  semantic checks :");
  for (const check of gate.semantic_checks) {
    console.log(`    - ${check.status.padEnd(13)} ${check.rule_id}: ${check.detail}`);
  }
}

function printEvaluation(evaluation: GateEvaluationReport): void {
  const gate1 = evaluation.gates.GATE_01_DEPOSIT_PRE_WIRE;
  const gate2 = evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE;
  const lc = evaluation.institutional_views.lc_mt700_check;
  const delta = evaluation.institutional_views.delta_ie_h1_pack;
  const deltaComplete = delta.data_elements.filter((element) => element.status === "COMPLETE").length;

  console.log("");
  console.log("SALTED BLIND INDEX (CROSS-LENDER DUPLICATE-PLEDGE TOKEN)");
  console.log(`  normalized tuple : ${evaluation.blind_index?.normalized_tuple ?? "n/a"}`);
  console.log(`  blind index      : ${evaluation.blind_index?.blind_index_hex ?? "n/a"}`);
  console.log(`  registry salt id : ${evaluation.blind_index?.registry_salt_id ?? "n/a"}`);

  printGate(gate1);
  printGate(gate2);

  console.log("");
  console.log("INSTITUTIONAL OUTPUT VIEWS");
  console.log(
    `  pre_wire_gate    : ${evaluation.institutional_views.pre_wire_gate.verdict} | advance ${evaluation.institutional_views.pre_wire_gate.advance_amount_eur.toFixed(2)} ${evaluation.institutional_views.pre_wire_gate.currency}`
  );
  console.log(
    `  lc_mt700_check   : ${lc.overall} | ${lc.checks.filter((check) => check.status === "PASS").length} PASS / ${lc.checks.filter((check) => check.status === "FAIL").length} FAIL / ${lc.checks.filter((check) => check.status === "NOT_EVALUATED").length} NOT_EVALUATED`
  );
  console.log(
    `  delta_ie_h1_pack : ${delta.overall} | ${deltaComplete}/${delta.data_elements.length} data elements complete`
  );

  console.log("");
  console.log("DETERMINISTIC VERDICT");
  if (gate1.verdict === "READY" && gate2.verdict === "READY") {
    console.log("  RELEASE AUTHORIZED: both deterministic gates returned READY.");
  } else {
    console.log("  RELEASE BLOCKED: at least one deterministic gate returned HARD_STOP.");
  }
}

function printHeader(dossier: OOES18Dossier, evaluation: GateEvaluationReport): void {
  console.log("========================================================================");
  console.log(" OOES-18 v1.1.0 :: OPEN ORIGIN EVIDENCE SCHEMA");
  console.log(" A model reads. A compiled kernel decides.");
  console.log("========================================================================");
  console.log(` dossier_id        : ${dossier.dossier_id}`);
  console.log(` tenant_id         : ${dossier.tenant_id}`);
  console.log(` reference_time    : ${dossier.reference_time}`);
  console.log(` dossier state root: ${dossier.dossier_state_root}`);
  console.log(
    ` seal verification : ${evaluation.seal_verification.ok ? "SEAL INTEGRITY OK (18 SLOTS EVALUATED)" : "INTEGRITY ERRORS PRESENT"}`
  );
  console.log("");
}

function runVerifyAttestations(): number {
  const dossier = loadDossier();
  const trustStore = loadTrustStore();
  let failures = 0;

  console.log("========================================================================");
  console.log(" OOES-18 v1.1.0 :: PUBLIC ATTESTATION VERIFICATION");
  console.log(" Tenant master secret: NOT REQUIRED");
  console.log("========================================================================");

  for (const slot of Object.values(dossier.slots)) {
    if (!slot.attestation || slot.payload === null) {
      continue;
    }
    const payloadHash = computeJcsSha256(slot.payload);
    const payloadMatch = slot.attestation.payload_jcs_sha256 === payloadHash;
    const signatureValid = verifyAttestationSignature(
      slot.slot_id,
      payloadHash,
      slot.attestation
    );
    const trusted = isTrustedAttester(
      trustStore,
      slot.attestation,
      slot.slot_id,
      dossier.reference_time
    );
    const ok =
      payloadMatch &&
      signatureValid &&
      (slot.state !== "CORROBORATED" || trusted);
    if (!ok) {
      failures += 1;
    }
    const label = ok
      ? slot.state === "CORROBORATED"
        ? "TRUSTED"
        : "SELF-DECLARED"
      : "FAILED";
    console.log(
      `${slot.slot_id}: ${label} | payload ${
        payloadMatch ? "MATCH" : "MISMATCH"
      } | signature ${signatureValid ? "VALID" : "INVALID"} | trust ${
        trusted ? "YES" : "NO"
      }`
    );
  }

  console.log("");
  console.log(
    failures === 0
      ? "RESULT: all attestations verify; every CORROBORATED slot is backed by a trusted key."
      : `RESULT: ${failures} attestation(s) failed public verification.`
  );
  return failures === 0 ? 0 : 1;
}

function runVerify(): number {
  const dossier = loadDossier();
  const evaluation = evaluateReleaseGates(
    dossier,
    MASTER_SECRET_HEX,
    dossier.reference_time,
    loadTrustStore()
  );
  printHeader(dossier, evaluation);
  printSlotTable(evaluation.seal_verification);
  printEvaluation(evaluation);
  return 0;
}

function runTamperDemo(): number {
  const dossier = loadDossier();
  const labSlot = dossier.slots["L3.S09_LAB_CERTIFICATE"];
  if (
    !labSlot ||
    !labSlot.payload ||
    typeof labSlot.payload.measured_cotton_pct !== "number"
  ) {
    console.error("Tamper demo requires a sealed L3.S09_LAB_CERTIFICATE payload.");
    return 1;
  }

  const originalCotton = labSlot.payload.measured_cotton_pct;
  labSlot.payload.measured_cotton_pct = 89.4;

  const evaluation = evaluateReleaseGates(
    dossier,
    MASTER_SECRET_HEX,
    dossier.reference_time,
    loadTrustStore()
  );
  const forged = evaluation.seal_verification.slots.find(
    (slot) => slot.slot_id === "L3.S09_LAB_CERTIFICATE"
  );
  const gate2 = evaluation.gates.GATE_02_BALANCE_AND_PRE_CLEARANCE;

  const hmacMismatch = forged !== undefined && !forged.hmac_sha256_match;
  const demoted = forged?.effective_state === "UNKNOWN";
  const gate2Halt = gate2.verdict === "HARD_STOP";

  console.log("========================================================================");
  console.log(" OOES-18 v1.1.0 :: TAMPER DEMONSTRATION");
  console.log("========================================================================");
  console.log(` dossier_id              : ${dossier.dossier_id}`);
  console.log(` target slot             : L3.S09_LAB_CERTIFICATE`);
  console.log(` original cotton_pct     : ${originalCotton}`);
  console.log(` forged cotton_pct       : 89.4`);
  console.log(` tenant master secret    : withheld from attacker`);
  console.log("");

  if (hmacMismatch && demoted && gate2Halt) {
    console.log(
      "[CRITICAL] SLOT L3.S09_LAB_CERTIFICATE: HMAC-SHA256 DIGEST MISMATCH -> EPISTEMIC DEMOTION (CORROBORATED -> UNKNOWN) -> GATE_02 HARD_STOP"
    );
  } else {
    console.log("[ERROR] Tamper demonstration failed to trigger deterministic demotion.");
  }

  console.log("");
  console.log("FORENSIC DETAIL");
  console.log(`  declared state        : ${forged?.declared_state ?? "UNKNOWN"}`);
  console.log(`  effective state       : ${forged?.effective_state ?? "UNKNOWN"}`);
  console.log(`  JCS SHA-256           : ${forged?.jcs_sha256_match ? "MATCH" : "MISMATCH"}`);
  console.log(`  HMAC-SHA256           : ${forged?.hmac_sha256_match ? "MATCH" : "MISMATCH"}`);
  console.log(`  AES-256-GCM           : ${forged?.aes_gcm_authenticated ? "VALID" : "INVALID"}`);
  console.log(`  fault codes           : ${forged?.fault_codes.join(", ") ?? "none"}`);
  console.log("");
  printGate(gate2);
  console.log("");
  console.log("SECURITY PROPERTY");
  console.log(
    "  A holder of the dossier bytes but not the tenant master secret cannot"
  );
  console.log(
    "  forge a compliant laboratory reading. The gate outcome is HKDF-bound."
  );

  return hmacMismatch && demoted && gate2Halt ? 0 : 1;
}

const mode = process.argv[2] ?? "verify";

if (mode === "verify") {
  process.exitCode = runVerify();
} else if (mode === "verify-attestations") {
  process.exitCode = runVerifyAttestations();
} else if (mode === "tamper-demo") {
  process.exitCode = runTamperDemo();
} else {
  console.error(
    `Unknown mode "${mode}". Expected "verify", "verify-attestations", or "tamper-demo".`
  );
  process.exitCode = 2;
}
