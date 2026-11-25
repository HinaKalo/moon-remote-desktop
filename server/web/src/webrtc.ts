/**
 * WebRTC remote viewer session: DTLS-SRTP H.264 video track + DataChannel carrying
 * SPAKE2-authenticated Moon Remote control messages bound to both DTLS fingerprints.
 */

import { bindingFromDtlsFingerprints, hexToBytes } from "./pake";

export interface TurnConfig {
  iceServers: RTCIceServer[];
}

export function extractDtlsFingerprintSha256(sdp: string): Uint8Array | null {
  const m = sdp.match(/a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/);
  if (!m) return null;
  return hexToBytes(m[1].replace(/:/g, ""));
}

export class WebRtcViewer {
  private pc: RTCPeerConnection;
  private dc: RTCDataChannel | null = null;
  private localFp: Uint8Array | null = null;
  private remoteFp: Uint8Array | null = null;

  onTrack?: (stream: MediaStream) => void;
  onDataOpen?: (binding: Uint8Array) => void;
  onDataMessage?: (data: Uint8Array) => void;
  onIceCandidate?: (cand: RTCIceCandidateInit) => void;
  onStateChange?: (state: RTCPeerConnectionState) => void;

  constructor(iceServers: RTCIceServer[]) {
    this.pc = new RTCPeerConnection({ iceServers });
    this.pc.ontrack = (ev) => {
      this.onTrack?.(ev.streams[0] ?? new MediaStream([ev.track]));
    };
    this.pc.onicecandidate = (ev) => {
      if (ev.candidate) this.onIceCandidate?.(ev.candidate.toJSON());
    };
    this.pc.onconnectionstatechange = () => {
      this.onStateChange?.(this.pc.connectionState);
    };
  }

  async createOffer(): Promise<RTCSessionDescriptionInit> {
    this.pc.addTransceiver("video", { direction: "recvonly" });
    this.dc = this.pc.createDataChannel("moonrd", { ordered: true });
    this.dc.binaryType = "arraybuffer";
    this.dc.onopen = () => {
      if (this.localFp && this.remoteFp) {
        this.onDataOpen?.(bindingFromDtlsFingerprints(this.localFp, this.remoteFp));
      }
    };
    this.dc.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        this.onDataMessage?.(new Uint8Array(ev.data));
      }
    };
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    if (offer.sdp) {
      this.localFp = extractDtlsFingerprintSha256(offer.sdp);
    }
    if (this.pc.iceGatheringState !== "complete") {
      await new Promise<void>((resolve) => {
        const finish = () => {
          clearTimeout(timer);
          this.pc.removeEventListener("icegatheringstatechange", changed);
          resolve();
        };
        const changed = () => { if (this.pc.iceGatheringState === "complete") finish(); };
        const timer = window.setTimeout(finish, 5500);
        this.pc.addEventListener("icegatheringstatechange", changed);
        changed();
      });
    }
    if (!this.pc.localDescription) throw new Error("Connection closed");
    return this.pc.localDescription.toJSON();
  }

  async setAnswer(answer: RTCSessionDescriptionInit): Promise<void> {
    if (answer.sdp) {
      this.remoteFp = extractDtlsFingerprintSha256(answer.sdp);
    }
    await this.pc.setRemoteDescription(answer);
  }

  async addIceCandidate(cand: RTCIceCandidateInit): Promise<void> {
    await this.pc.addIceCandidate(cand);
  }

  sendControl(bytes: Uint8Array): boolean {
    if (this.dc?.readyState !== "open") return false;
    try {
      this.dc.send(bytes.slice());
      return true;
    } catch {
      return false;
    }
  }

  close(): void {
    this.pc.onconnectionstatechange = null;
    this.pc.ontrack = null;
    this.dc?.close();
    this.pc.close();
  }
}
