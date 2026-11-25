"""Run the ignored moonrd-service QA tests on two machines through an SSH UDP relay.

Pass the local and compatible Linux `cargo test -p moonrd-service --lib --no-run`
executables. The browser check uses the running local Vite app and Playwright.
"""

import argparse
import base64
import heapq
import ipaddress
import json
import os
from pathlib import Path
import queue
import random
import re
import shlex
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time


def start_thread(fn):
    threading.Thread(target=fn, daemon=True).start()


def local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 9))
        return route.getsockname()[0]


def udp_packets(stream):
    while header := stream.read(2):
        size, = struct.unpack("!H", header)
        payload = stream.read(size)
        if len(payload) != size:
            return
        yield payload


def write_packet(stream, packet):
    stream.write(struct.pack("!H", len(packet)) + packet)
    stream.flush()


def remote_udp(use_loopback):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1" if use_loopback else local_ip(), 0))
        print(*udp.getsockname(), flush=True)
        host, port = sys.stdin.buffer.readline().decode().split()
        udp.connect((host, int(port)))

        def forward():
            try:
                for packet in udp_packets(sys.stdin.buffer):
                    udp.send(packet)
            finally:
                os._exit(0)

        start_thread(forward)
        while True:
            write_packet(sys.stdout.buffer, udp.recv(65535))


class Delay:
    def __init__(self, send, latency_ms, loss, seed):
        self.send = send
        self.rng = random.Random(seed)
        self.latency = latency_ms / 1000
        self.loss = loss
        self.drops = 0
        self.pending = []
        self.lock = threading.Condition()
        self.closed = False
        start_thread(self.drain)

    def add(self, packet):
        with self.lock:
            if self.closed:
                return
            if self.rng.random() < self.loss:
                self.drops += 1
                return
            due = time.monotonic() + self.latency + self.rng.uniform(-0.008, 0.008)
            heapq.heappush(self.pending, (due, packet))
            self.lock.notify()

    def drain(self):
        while True:
            with self.lock:
                while not self.pending and not self.closed:
                    self.lock.wait()
                if self.closed:
                    return
                due, packet = self.pending[0]
                if (remaining := due - time.monotonic()) > 0:
                    self.lock.wait(remaining)
                    continue
                heapq.heappop(self.pending)
            try:
                self.send(packet)
            except (BrokenPipeError, OSError):
                return

    def stop(self):
        with self.lock:
            self.closed = True
            self.lock.notify()


class Relay:
    def __init__(self, ssh, remote_script, native):
        command = f"python3 -u {shlex.quote(remote_script)} --remote-udp {'loopback' if native else 'webrtc'}"
        self.proc = subprocess.Popen([*ssh, command], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        remote_host, remote_port = self.proc.stdout.readline().decode().split()
        self.remote_addr = (remote_host, int(remote_port))
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1" if native else local_ip(), 0))
        self.local_addr = self.udp.getsockname()
        self.viewer = None
        self.drop_media = False
        self.media_drops = 0
        self.lost_rtp = set()
        self.rtx_payload_types = set()
        self.up = Delay(lambda p: write_packet(self.proc.stdin, p), 70, 0.05 if native else 0, 17)
        self.down = Delay(lambda p: self.udp.sendto(p, self.viewer) if self.viewer else None,
                          70, 0.05 if native else 0, 23)

    def connect(self, host_addr):
        self.proc.stdin.write(f"{host_addr[0]} {host_addr[1]}\n".encode())
        self.proc.stdin.flush()
        start_thread(self.from_viewer)
        start_thread(self.from_host)

    def from_viewer(self):
        try:
            while True:
                payload, self.viewer = self.udp.recvfrom(65535)
                self.up.add(payload)
        except OSError:
            pass

    def from_host(self):
        for packet in udp_packets(self.proc.stdout):
            is_rtp = len(packet) >= 12 and packet[0] >> 6 == 2 and not 192 <= packet[1] <= 223
            if is_rtp:
                identity = (packet[8:12], packet[2:4])  # SSRC and sequence number
                if self.drop_media:
                    self.lost_rtp.add(identity)
                if identity in self.lost_rtp or (self.lost_rtp and (packet[1] & 0x7f) in self.rtx_payload_types):
                    self.media_drops += 1
                    continue
            self.down.add(packet)

    def close(self):
        self.up.stop()
        self.down.stop()
        self.udp.close()
        try:
            self.proc.stdin.close()
        except OSError:
            pass  # The remote relay can already have exited on an ICE failure.
        self.proc.wait(timeout=8)


class Probe:
    def __init__(self, argv, env=None):
        self.proc = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.lines = queue.Queue()
        self.events = []

        def collect():
            for line in self.proc.stdout:
                if line.startswith("QA_"):
                    event = (time.monotonic(), line.split())
                    self.events.append(event)
                    self.lines.put(event)

        start_thread(collect)

    def wait_for(self, prefix, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _, line = self.lines.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line[0] == prefix:
                return line[1:]
        raise RuntimeError(f"Timed out waiting for {prefix}; host events: {self.events}")

    def send(self, value):
        self.proc.stdin.write(value + "\n")
        self.proc.stdin.flush()

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def run_quic(args, ssh, remote_dir):
    host = Probe([*ssh, f"{remote_dir}/probe --ignored qa_host --nocapture"])
    relay = None
    viewer = None
    try:
        port, key = host.wait_for("QA_READY")
        relay = Relay(ssh, f"{remote_dir}/relay.py", native=True)
        relay.connect(("127.0.0.1", int(port)))
        env = dict(os.environ, MRD_QA_ADDRESS="%s:%s" % relay.local_addr, MRD_QA_KEY=key)
        viewer = Probe([args.local_bin, "--ignored", "qa_quic_viewer", "--nocapture"], env)
        assert viewer.proc.wait(timeout=35) == 0, "QUIC viewer failed"
        sent = {int(line[1]): t for t, line in viewer.events if line[0] == "QA_SENT"}
        result = {"loss_percent_each_direction": 5, "added_rtt_ms": 140,
                  "dropped_packets": relay.up.drops + relay.down.drops}
        for kind in ("QA_KEY", "QA_CLICK"):
            received = {int(line[1]): t for t, line in host.events if line[0] == kind}
            assert sent.keys() == received.keys() and len(sent) == 10, (kind, sent, received)
            times = sorted((received[key] - t) * 1000 for key, t in sent.items())
            assert times[-1] < 1200, (kind, times)
            result[kind] = {"count": len(times), "median_ms": round(statistics.median(times)), "max_ms": round(times[-1])}
        return result
    finally:
        if viewer:
            viewer.close()
        if relay:
            relay.close()
        host.close()


def rewrite_candidates(sdp, addr, preferred_target=None):
    pattern = r"^(a=candidate:\S+ 1 udp \d+) (\S+) (\d+)( typ host[^\r\n]*)"
    candidates = []
    for _, host, port, _ in re.findall(pattern, sdp, flags=re.MULTILINE | re.IGNORECASE):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            continue
        candidates.append((host, int(port)))
    target = next((item for item in candidates if item[0] == preferred_target), candidates[0] if candidates else None)
    modified = re.sub(pattern, lambda m: f"{m[1]} {addr[0]} {addr[1]} typ host", sdp, flags=re.MULTILINE | re.IGNORECASE)
    return modified, target


def browser_fixture(page):
    return page.evaluate("""async () => {
        const width = 640, height = 360;
        const canvas = new OffscreenCanvas(width,height), ctx = canvas.getContext('2d');
        const config = {codec:'avc1.42001f',width,height,framerate:30,bitrate:1600000,
            latencyMode:'realtime',avc:{format:'annexb'}};
        const frames = [];
        const enc = new VideoEncoder({output(chunk) {
            const bytes = new Uint8Array(chunk.byteLength); chunk.copyTo(bytes);
            let text = ''; for (const b of bytes) text += String.fromCharCode(b);
            frames.push(btoa(text));
        },error(error) { throw error; }});
        enc.configure(config);
        for (let i = 0; i < 450; i++) {
            ctx.fillStyle='#182855'; ctx.fillRect(0,0,width,height);
            ctx.fillStyle='#e3aa4e'; ctx.fillRect((i*7)%560,80,80,180);
            ctx.fillStyle='white'; ctx.font='48px sans-serif'; ctx.fillText(String(i),40,310);
            const frame = new VideoFrame(canvas,{timestamp:i*33333});
            enc.encode(frame,{keyFrame:i===0}); frame.close();
            while (enc.encodeQueueSize > 8) await new Promise(r => setTimeout(r, 5));
        }
        await enc.flush(); enc.close();
        return frames;
    }""")


def wait_stats(page, expression, ready, timeout=6):
    deadline = time.monotonic() + timeout
    stats = None
    while time.monotonic() < deadline:
        stats = page.evaluate(expression)
        if stats and ready(stats):
            return stats
        page.wait_for_timeout(35)
    raise RuntimeError(f"Browser stats did not reach the expected state: {stats}")


def run_browser(args, ssh, remote_dir):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.edge, headless=True)
        page = browser.new_page()
        page.goto(args.web)
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / "fixture.json"
            fixture.write_text(json.dumps(browser_fixture(page)), encoding="utf-8")
            subprocess.run(["scp", str(fixture), f"{args.ssh}:{remote_dir}/fixture.json"], check=True)
        host = Probe([*ssh, f"MRD_QA_H264={remote_dir}/fixture.json {remote_dir}/probe --ignored qa_host --nocapture"])
        relay = None
        try:
            host.wait_for("QA_READY")
            relay = Relay(ssh, f"{remote_dir}/relay.py", native=False)

            def answer(invite):
                offer, _ = rewrite_candidates(invite["data"]["sdp"], relay.remote_addr)
                host.send(base64.b64encode(offer.encode()).decode())
                sdp = base64.b64decode(host.wait_for("QA_ANSWER")[0]).decode()
                relay.rtx_payload_types = set(map(int, re.findall(r"^a=rtpmap:(\d+) rtx/90000", sdp, re.MULTILINE | re.IGNORECASE)))
                rewritten, target = rewrite_candidates(sdp, relay.local_addr, relay.remote_addr[0])
                if not target:
                    raise RuntimeError("Host answer contains no UDP host candidate")
                relay.connect(target)
                return {"type": "sdp", "session": invite["session"], "from": "qa-host",
                        "data": {"type": "answer", "sdp": rewritten}}

            page.expose_function("qaAnswer", answer)
            page.evaluate("""async () => {
                const real = window.RTCPeerConnection;
                window.RTCPeerConnection = class extends real { constructor(...args) { super(...args); window.qaPeer = this; } };
                window.WebSocket = class {
                    constructor() { setTimeout(() => this.onopen?.(),0); }
                    send(payload) {
                        window.qaAnswer(JSON.parse(payload)).then(msg => this.onmessage?.({data:JSON.stringify(msg)}),
                            error => this.onerror?.(error));
                    }
                    close() { this.onclose?.(); }
                };
                const {showSession} = await import('/src/viewer-session.ts');
                showSession({id:'qa-host',name:'QA host'}, path => Promise.resolve(
                    path === '/v1/turn' ? {iceServers:[]} : {ticket:'qa'}));
            }""")
            page.locator("dialog input[type=password]").fill("581739")
            page.get_by_role("button", name="连接", exact=True).click()
            page.wait_for_function("document.querySelector('video').videoWidth > 0", timeout=30000)
            page.evaluate("""() => {
                const video = document.querySelector('video'); window.qaPresented = 0;
                const next = () => { window.qaPresented++; video.requestVideoFrameCallback(next); };
                video.requestVideoFrameCallback(next);
            }""")
            stats_expr = """async () => {
                const inbound = [...(await window.qaPeer.getStats()).values()].find(s => s.type === 'inbound-rtp' && s.kind === 'video');
                return {...inbound, presented: window.qaPresented};
            }"""
            before = wait_stats(page, stats_expr, lambda s: s["presented"] >= 15)
            request_count = lambda: sum(line[0] == "QA_REQUEST" for _, line in host.events)
            before_requests = request_count()
            relay.drop_media = True
            page.wait_for_timeout(850)
            relay.drop_media = False
            start = time.monotonic()
            def feedback(stats):
                return stats.get("pliCount", 0) + stats.get("firCount", 0)

            after = wait_stats(page, stats_expr, lambda s: s["keyFramesDecoded"] > before["keyFramesDecoded"]
                               and s["presented"] > before["presented"] and feedback(s) > feedback(before))
            result = {"added_rtt_ms": 140, "dropped_rtp_packets": relay.media_drops, "blackout_ms": 850,
                      "recovered_ms": round((time.monotonic() - start) * 1000), "keyframe_requests_delta": request_count() - before_requests,
                      "pli_delta": after.get('pliCount', 0) - before.get('pliCount', 0),
                      "fir_delta": after.get('firCount', 0) - before.get('firCount', 0),
                      "decoded_keyframes_delta": after['keyFramesDecoded'] - before['keyFramesDecoded']}
            assert result["dropped_rtp_packets"] > 0 and result["keyframe_requests_delta"] > 0, result
            return result
        finally:
            browser.close()
            if relay:
                relay.close()
            host.close()


def main():
    if sys.argv[1:2] == ["--remote-udp"]:
        remote_udp(sys.argv[2] == "loopback")
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("local_bin")
    parser.add_argument("linux_bin")
    parser.add_argument("--ssh", required=True)
    parser.add_argument("--edge")
    parser.add_argument("--web", default="http://127.0.0.1:5184")
    parser.add_argument("--mode", choices=("quic", "browser", "both"), default="both")
    args = parser.parse_args()
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", args.ssh]
    remote_dir = subprocess.check_output([*ssh, "mktemp -d /tmp/moonrd-qa.XXXXXXXX"], text=True).strip()
    if not re.fullmatch(r"/tmp/moonrd-qa\.[A-Za-z0-9]+", remote_dir):
        raise RuntimeError("Unexpected test directory")
    try:
        for source, name in ((args.linux_bin, "probe"), (__file__, "relay.py")):
            subprocess.run(["scp", source, f"{args.ssh}:{remote_dir}/{name}"], check=True)
        subprocess.run([*ssh, f"chmod u+x {remote_dir}/probe"], check=True)
        if args.mode in ("quic", "both"):
            print(json.dumps({"quic": run_quic(args, ssh, remote_dir)}), flush=True)
        if args.mode in ("browser", "both"):
            print(json.dumps({"browser": run_browser(args, ssh, remote_dir)}), flush=True)
    finally:
        subprocess.run([*ssh, f"rm -f {remote_dir}/probe {remote_dir}/relay.py {remote_dir}/fixture.json; rmdir {remote_dir}"], check=True)


if __name__ == "__main__":
    main()
