/**
 * Moon Remote SPAKE2 (Ed25519 group, RustCrypto spake2 0.4 / python-spake2 compatible),
 * Argon2id PIN derivation, channel bindings, and key confirmation schedule.
 *
 * Verified byte-for-byte against `core/crates/moonrd-session/testdata/pake-vectors.json`.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { argon2id } from "@noble/hashes/argon2";
import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";

const Point = ed25519.ExtendedPoint;
const CURVE_ORDER = ed25519.CURVE.n;

// RustCrypto spake2 0.4 Ed25519Group::const_m / const_n
const POINT_M = Point.fromHex(
  "15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312"
);
const POINT_N = Point.fromHex(
  "f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3"
);

const SIDE_A = 0x41; // 'A' (viewer)
const SIDE_B = 0x42; // 'B' (host)

const enc = new TextEncoder();

export type Role = "viewer" | "host";

export enum AuthMethod {
  Unspecified = 0,
  Pin = 1,
  Pairing = 2,
  SupportCode = 3,
}

export interface KdfParams {
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export function derivePinSecret(
  pin: string,
  salt: Uint8Array,
  params: KdfParams = { memoryKib: 19456, iterations: 2, parallelism: 1 }
): Uint8Array {
  return argon2id(enc.encode(pin), salt, {
    m: params.memoryKib,
    t: params.iterations,
    p: params.parallelism,
    dkLen: 32,
  });
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function hashBinding(kind: string, parts: Uint8Array[]): Uint8Array {
  const chunks: Uint8Array[] = [enc.encode("moonrd/v1 binding "), enc.encode(kind)];
  for (const p of parts) {
    chunks.push(u32be(p.length), p);
  }
  return sha256(concatBytes(...chunks));
}

export function bindingFromTlsExporter(ekm: Uint8Array): Uint8Array {
  return hashBinding("tls-exporter", [ekm]);
}

export function bindingFromDtlsFingerprints(
  viewerFp: Uint8Array,
  hostFp: Uint8Array
): Uint8Array {
  return hashBinding("dtls-fingerprints", [viewerFp, hostFp]);
}

function makeIdentity(role: Role, method: AuthMethod, binding: Uint8Array): Uint8Array {
  const prefix = enc.encode(role === "viewer" ? "moonrd/v1/viewer/" : "moonrd/v1/host/");
  return concatBytes(prefix, new Uint8Array([method & 0xff, 0x2f /* '/' */]), binding);
}

function bytesLeToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(bytes[i]);
  }
  return acc;
}

function bytesBeToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = 0; i < bytes.length; i++) {
    acc = (acc << 8n) | BigInt(bytes[i]);
  }
  return acc;
}

function modL(v: bigint): bigint {
  const r = v % CURVE_ORDER;
  return r >= 0n ? r : r + CURVE_ORDER;
}

/**
 * Matches RustCrypto spake2 0.4 `ed25519_hash_to_scalar`:
 * HKDF-SHA256(salt="", ikm=pw, info="SPAKE2 pw", len=48), interpreted as big-endian mod l.
 */
function passwordToScalar(pw: Uint8Array): bigint {
  const okm = hkdf(sha256, pw, new Uint8Array(0), enc.encode("SPAKE2 pw"), 48);
  return modL(bytesBeToBigInt(okm));
}

/**
 * Matches curve25519-dalek `Scalar::from_bytes_mod_order_wide` (64 little-endian bytes mod l).
 */
export function scalarFromWideLe(bytes64: Uint8Array): bigint {
  if (bytes64.length !== 64) {
    throw new Error("expected 64 random bytes for wide scalar");
  }
  return modL(bytesLeToBigInt(bytes64));
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export interface PakeKeys {
  confirmation: Uint8Array;
  sessionKey: Uint8Array;
  verifyPeer(tag: Uint8Array): boolean;
}

export class Pake {
  private readonly role: Role;
  private readonly pw: Uint8Array;
  private readonly pwScalar: bigint;
  private readonly idA: Uint8Array;
  private readonly idB: Uint8Array;
  private readonly scalar: bigint;
  private readonly myPointBytes: Uint8Array;

  private constructor(
    role: Role,
    method: AuthMethod,
    secret: Uint8Array,
    binding: Uint8Array,
    random64: Uint8Array
  ) {
    this.role = role;
    this.pw = new Uint8Array(secret);
    this.pwScalar = passwordToScalar(secret);
    this.idA = makeIdentity("viewer", method, binding);
    this.idB = makeIdentity("host", method, binding);
    this.scalar = scalarFromWideLe(random64);

    const blind = role === "viewer" ? POINT_M : POINT_N;
    const basePart = this.scalar === 0n ? Point.ZERO : Point.BASE.multiply(this.scalar);
    const pwPart = this.pwScalar === 0n ? Point.ZERO : blind.multiply(this.pwScalar);
    this.myPointBytes = basePart.add(pwPart).toRawBytes();
  }

  static start(
    role: Role,
    method: AuthMethod,
    secret: Uint8Array,
    binding: Uint8Array,
    random64?: Uint8Array
  ): { pake: Pake; message: Uint8Array } {
    const rnd = random64 ?? crypto.getRandomValues(new Uint8Array(64));
    const pake = new Pake(role, method, secret, binding, rnd);
    const side = role === "viewer" ? SIDE_A : SIDE_B;
    const message = concatBytes(new Uint8Array([side]), pake.myPointBytes);
    return { pake, message };
  }

  finish(peerMessage: Uint8Array): PakeKeys {
    if (peerMessage.length !== 33) {
      throw new Error("malformed SPAKE2 message length");
    }
    const expectedSide = this.role === "viewer" ? SIDE_B : SIDE_A;
    if (peerMessage[0] !== expectedSide) {
      throw new Error("unexpected SPAKE2 side byte");
    }
    const peerPointBytes = peerMessage.subarray(1);
    const peerPoint = Point.fromHex(peerPointBytes);
    const peerBlind = this.role === "viewer" ? POINT_N : POINT_M;
    const negPw = modL(-this.pwScalar);
    const unblinded =
      negPw === 0n ? peerPoint : peerPoint.add(peerBlind.multiply(negPw));
    const sharedPoint =
      this.scalar === 0n ? Point.ZERO : unblinded.multiply(this.scalar);
    const kBytes = sharedPoint.toRawBytes();

    const firstMsg = this.role === "viewer" ? this.myPointBytes : peerPointBytes;
    const secondMsg = this.role === "viewer" ? peerPointBytes : this.myPointBytes;

    // RustCrypto spake2 0.4 `hash_ab`:
    // sha256(sha256(pw) || sha256(idA) || sha256(idB) || X_msg || Y_msg || K_bytes)
    const transcript = concatBytes(
      sha256(this.pw),
      sha256(this.idA),
      sha256(this.idB),
      firstMsg,
      secondMsg,
      kBytes
    );
    const k = sha256(transcript);

    const viewerTag = hmac(sha256, k, enc.encode("moonrd/v1 confirm viewer"));
    const hostTag = hmac(sha256, k, enc.encode("moonrd/v1 confirm host"));
    const sessionKey = hmac(sha256, k, enc.encode("moonrd/v1 session"));

    const mine = this.role === "viewer" ? viewerTag : hostTag;
    const peer = this.role === "viewer" ? hostTag : viewerTag;

    return {
      confirmation: mine,
      sessionKey,
      verifyPeer(tag: Uint8Array): boolean {
        return constantTimeEqual(tag, peer);
      },
    };
  }
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
