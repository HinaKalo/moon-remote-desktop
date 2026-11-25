import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it } from "vitest";
import {
  AuthMethod,
  Pake,
  bindingFromDtlsFingerprints,
  bindingFromTlsExporter,
  bytesToHex,
  derivePinSecret,
  hexToBytes,
} from "./pake";

interface VectorsFile {
  kdf: {
    pin: string;
    salt: string;
    memoryKib: number;
    iterations: number;
    parallelism: number;
    w: string;
  };
  bindings: {
    tlsExporter: { ekm: string; binding: string };
    dtlsFingerprints: { viewer: string; host: string; binding: string };
  };
  handshakes: Array<{
    name: string;
    method: number;
    binding: string;
    viewerSecret: string;
    hostSecret: string;
    viewerRngSeed: string;
    hostRngSeed: string;
    viewerMessage: string;
    hostMessage: string;
    viewerConfirmation: string;
    hostConfirmation: string;
    sessionKeyViewer: string;
    sessionKeyHost: string;
    viewerAccepts: boolean;
    hostAccepts: boolean;
  }>;
}

/** Matches Rust's deterministic vector RNG: SHA-256(seed || u64be counter). */
function deterministicBytes64(seed: string): Uint8Array {
  const seedBytes = new TextEncoder().encode(seed);
  const out = new Uint8Array(64);
  for (let block = 0; block < 2; block++) {
    const input = new Uint8Array(seedBytes.length + 8);
    input.set(seedBytes, 0);
    new DataView(input.buffer).setBigUint64(seedBytes.length, BigInt(block), false);
    out.set(sha256(input), block * 32);
  }
  return out;
}

const vectorsPath = resolve(
  __dirname,
  "../../../core/crates/moonrd-session/testdata/pake-vectors.json"
);
const vectors: VectorsFile = JSON.parse(readFileSync(vectorsPath, "utf-8"));

describe("Rust <-> TypeScript SPAKE2 & Argon2id test vectors", () => {
  it("matches Argon2id PIN KDF vector byte-for-byte", () => {
    const w = derivePinSecret(vectors.kdf.pin, hexToBytes(vectors.kdf.salt), {
      memoryKib: vectors.kdf.memoryKib,
      iterations: vectors.kdf.iterations,
      parallelism: vectors.kdf.parallelism,
    });
    expect(bytesToHex(w)).toBe(vectors.kdf.w);
  });

  it("matches TLS exporter and DTLS fingerprint bindings byte-for-byte", () => {
    const tls = bindingFromTlsExporter(hexToBytes(vectors.bindings.tlsExporter.ekm));
    expect(bytesToHex(tls)).toBe(vectors.bindings.tlsExporter.binding);

    const dtls = bindingFromDtlsFingerprints(
      hexToBytes(vectors.bindings.dtlsFingerprints.viewer),
      hexToBytes(vectors.bindings.dtlsFingerprints.host)
    );
    expect(bytesToHex(dtls)).toBe(vectors.bindings.dtlsFingerprints.binding);
  });

  for (const h of vectors.handshakes) {
    it(`matches handshake vector "${h.name}" byte-for-byte`, () => {
      const binding = hexToBytes(h.binding);
      const { pake: viewer, message: vMsg } = Pake.start(
        "viewer",
        h.method as AuthMethod,
        hexToBytes(h.viewerSecret),
        binding,
        deterministicBytes64(h.viewerRngSeed)
      );
      const { pake: host, message: hMsg } = Pake.start(
        "host",
        h.method as AuthMethod,
        hexToBytes(h.hostSecret),
        binding,
        deterministicBytes64(h.hostRngSeed)
      );

      expect(bytesToHex(vMsg)).toBe(h.viewerMessage);
      expect(bytesToHex(hMsg)).toBe(h.hostMessage);

      const vk = viewer.finish(hMsg);
      const hk = host.finish(vMsg);

      expect(bytesToHex(vk.confirmation)).toBe(h.viewerConfirmation);
      expect(bytesToHex(hk.confirmation)).toBe(h.hostConfirmation);
      expect(bytesToHex(vk.sessionKey)).toBe(h.sessionKeyViewer);
      expect(bytesToHex(hk.sessionKey)).toBe(h.sessionKeyHost);
      expect(vk.verifyPeer(hk.confirmation)).toBe(h.viewerAccepts);
      expect(hk.verifyPeer(vk.confirmation)).toBe(h.hostAccepts);
    });
  }
});
