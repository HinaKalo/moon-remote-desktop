# Phase 0b — media pipeline spike: go/no-go report

**Verdict: GO** (details in [Go/no-go](#gono-go)).

Machine: Windows 11 Pro 26200, AMD Ryzen 7 7800X3D (16 logical CPUs), AMD Radeon RX 9070 XT
(driver 32.0.32029.2010), primary display 2560×1440 @ 60 Hz. Browser: Microsoft Edge 157
(Chromium), plus the Chromium 156 browser pane of the Claude desktop app for the input test.
Everything runs on one machine (localhost). No LAN test across two machines was run.

## Results (localhost, 1920×1080 encode of a 2560×1440 desktop, H.264 Constrained Baseline)

**Latency target (< 60 ms on LAN/localhost): met at 1080p60 (p50 35 ms, p95 48 ms) and on the
median at 1080p30 (p50 52 ms, p95 64 ms).** The native viewer is roughly 7–23 ms faster than the
browser.

All archived runs (`results/`) were taken while a **RustDesk session was also capturing and
encoding this desktop** (≈ 6.5–8.5 % of the GPU video-codec engine and 4–8 % of 3D from other
processes; see "other processes GPU" in `python tools/summarize.py`). They are therefore
measured under competing load. An unarchived smoke run without RustDesk
(native viewer, 1080p60) gave paint→glass **p50 21 ms / p95 21.6 ms**. Browser runs before
RustDesk appeared gave p50 ~36 ms / p95 ~53 ms, about the same as below.

### Glass-to-glass (paint of the timestamp on the host → picture displayed on the viewer)

| Run (≈ 60 s, steady state) | p50 | p95 | mean | min–max | of which paint→RTP receive (p50 / p95) |
|---|---|---|---|---|---|
| **Browser 1080p60**, AMD HW encoder, Edge 157 | **35.0 ms** | **47.8 ms** | 32.3 | 16.8–84.9 | 10.7 / 27.4 |
| **Browser 1080p30**, AMD HW encoder | **52.0 ms** | 63.7 ms | 47.4 | 33.2–101.3 | 20.5 / 36.5 |
| Browser 1080p30, **software** encoder fallback | 51.7 ms | 75.4 ms | 48.6 | 33.5–102.6 | 20.8 / 49.5 |
| **Native viewer 1080p60** (MF D3D11 decode → Win32 flip swap chain) | **28.1 ms** | 45.5 ms | – | – | paint→decoded p50 17.9 |
| Native viewer 1080p30 | 29.1 ms | 34.6 ms | – | – | paint→decoded p50 19.4 |
| Native viewer 1080p60, *no RustDesk* (smoke run, not archived) | 21.0 ms | 21.6 ms | – | – | paint→decoded p50 12.4 |

How it is measured: a topmost window paints the epoch-ms time as a barcode about 4 ms before each
DWM composition. The browser decodes the barcode from every displayed frame in
`requestVideoFrameCallback` and compares it with `performance.timeOrigin + expectedDisplayTime`,
corrected by the clock offset that the data-channel ping estimates (≈ 0 on localhost). The native
viewer reads the barcode back from its back buffer and timestamps after `Present` + `DwmFlush`.
Neither side includes the monitor's own scan-out or pixel response. The host-side wait from
paint to composition (4.2–4.9 ms average, measured with `DwmFlush`) *is* included, so the
"composited-on-host → displayed-on-viewer" figure is about 4–5 ms lower (≈ 31 ms p50 at 1080p60).
Stamps were decoded on 100 % of frames (0 checksum failures over 7,000+ frames).

### Where the time goes (host, per frame, averages)

| Stage | 1080p60 | 1080p30 |
|---|---|---|
| DWM present → frame acquired (0 ms poll + 1 ms sleep) | 0.75 ms | 0.85 ms |
| GPU copy + video-processor scale/convert (CPU submit) | 0.13 ms | 0.17 ms |
| `ProcessInput` → bitstream out (AMD MFT, async) | 4.8 ms | 5.1 ms |
| DWM present → encoded bitstream (incl. slot wait at 30 fps) | 7.8 ms | 12.4 ms |
| bitstream → last RTP packet sent (str0m packetize + SRTP + UDP) | 0.03 ms | 0.06 ms |
| Browser: receive → expected display (decode + Chromium render pipeline) | ≈ 24 ms | ≈ 31 ms |
| Browser jitter buffer (`getStats`), decode time | 0.66 ms, 0.32 ms | 0.57 ms, 0.31 ms |
| Data-channel input echo RTT (pointer move → host → page) | p50 4.2 ms / p95 6.0 | p50 0.7 ms / p95 3.1 |

Also measured, from the browser pane of the Claude app: input echo RTT p50 2.5 ms. Every run had
0 packets lost and 0 frames dropped, and the encoder dropped 0 frames before encoding. Rate
control: the hardware encoder held 11.9 Mbit/s (target 12) and 8.0 (target 8). The software MFT
ignored the CBR target on a mostly static screen (≈ 1.4 Mbit/s average, bursty).

### CPU / GPU (16 logical CPUs; `tools/usage.ps1`, 30 s windows)

| Run | Host CPU (machine / one core) | Browser CPU (machine / one core) | Host GPU: video codec / 3D | Browser GPU: video codec / 3D (high prio) |
|---|---|---|---|---|
| Browser 1080p60, HW | 0.67 % / 10.7 % | 2.32 % / 37.1 % | 13.1 % / 1.7 % | 7.9 % / 5.1 % |
| Browser 1080p30, HW | 0.43 % / 6.9 % | 1.17 % / 18.7 % | 6.7 % / 1.2 % | 3.9 % / 2.7 % |
| Browser 1080p30, **SW encoder** | 2.49 % / 39.9 % | 1.43 % / 22.8 % | 0 % / 1.8 % | 4.0 % / 2.7 % |
| Native 1080p60 (encode + decode + present in one process) | 0.65 % / 10.4 % | – | 21.4 % / 5.9 % | – |
| Native 1080p30 | 0.43 % / 6.8 % | – | 12.2 % / 3.7 % | – |

Encoder selection (logged at start): `MFTEnumEx(HARDWARE)` returned **`AMDh264Encoder`** twice
(one per adapter/LUID; ours is sorted first) → async, D3D11-aware, **Constrained Baseline**
accepted, and every `ICodecAPI` property accepted. Software fallback: **"H264 Encoder MFT"**
(Microsoft, sync, not D3D-aware: MF reads the NV12 texture back to system memory). It runs at
3.75 ms/frame at 1080p30 on the 7800X3D. It rejects `MFT_MESSAGE_COMMAND_FLUSH` before streaming,
so that message is best-effort.


## What was built

`spikes/media/` is a standalone Cargo project (its own `[workspace]`, not part of `core/`):

```
cargo run --release            # 1080p60, hardware encoder, overlay on, http://localhost:8080/
cargo run --release -- --fps 30 --native --label mytest
```

Open `http://localhost:8080/` in Chrome or Edge: the page shows the live primary desktop, a
latency panel, and a green dot that follows the mouse *as echoed by the host* over the data
channel. Flags: `--fps`, `--width/--height` (encode size, default 1920×1080), `--kbps`
(default 12000 at 60 fps, 8000 at 30 fps), `--encoder hw|sw`, `--high` (High profile),
`--speed 0..100` (`QualityVsSpeed`, default 0), `--native` (native viewer window),
`--no-overlay`, `--port`, `--ip`, `--label <name>` (write `results/<name>-*.jsonl`), `--open`.
Plain `cargo run` (dev profile, opt-level 1) also works; the numbers below use `--release`.

| Stage | Implementation | File |
|---|---|---|
| Capture | DXGI Desktop Duplication (`IDXGIOutput1::DuplicateOutput`) on the adapter that owns the primary output. Desktop BGRA → `CopyResource` → private BGRA → `ID3D11VideoProcessor` (scale 2560×1440→1920×1080 + RGB→NV12 BT.709 limited) → ring of 8 NV12 textures. **No CPU copies**: frames stay on the GPU until the encoder's bitstream. | `src/capture.rs`, `src/gpu.rs` |
| Pacing | Fixed cadence phase-locked to vsync. The newest desktop image is always kept, so a capped frame rate never loses the last change on a static screen. A static screen re-sends the last frame every 200 ms. | `src/capture.rs` |
| Encode | Media Foundation H.264 encoder MFT, enumerated with `MFTEnumEx(HARDWARE \| SORTANDFILTER)`, falling back to the synchronous Microsoft software MFT. Async MFT driven by an event-pump thread. D3D11 input via `MFCreateDXGISurfaceBuffer` and `MFT_MESSAGE_SET_D3D_MANAGER`. `ICodecAPI`: `AVLowLatencyMode=1`, CBR, VBV = ½ s, `BPictureCount=0`, GOP = 10 s, `QualityVsSpeed=0`, `AVEncVideoForceKeyFrame` on PLI/FIR, new viewers and decoder start. Constrained Baseline. SPS/PPS are prepended from `MF_MT_MPEG_SEQUENCE_HEADER` if a keyframe lacks them. | `src/encoder.rs` |
| WebRTC | str0m 0.25 (sans-IO). The browser offers (recvonly video plus one unordered, unreliable data channel); the host answers with one UDP host candidate on the default-route interface. Each session runs on its own thread with one queue fed by a UDP reader thread and the encoder hub. Header extensions: playout-delay = 0/0 (Chromium's low-latency renderer) and abs-capture-time. Sessions end on data-channel close or 5 s of peer silence. | `src/rtc.rs` |
| Signalling / page | `tiny_http`: `GET /` (page), `GET /config`, `POST /offer`, `POST /stats`. The page sets `jitterBufferTarget = 0`, measures per frame with `requestVideoFrameCallback`, and posts 5 s summaries plus `getStats()` inbound-rtp deltas. | `src/main.rs`, `web/index.html` |
| Input path | Pointer moves → data channel → host echoes the JSON with its receive timestamp → the page draws a dot at the echoed position and records the RTT. The same channel runs an NTP-style ping (min-RTT sample) to estimate the host↔browser clock offset, so the method also works across two machines. | `src/rtc.rs`, `web/index.html` |
| Native viewer | Microsoft H.264 decoder MFT (`CLSID_MSH264DecoderMFT`) in D3D11/DXVA mode on a **separate** D3D11 device → `ID3D11VideoProcessor` NV12→BGRA straight into a flip-discard swap chain (`DXGI_SCALING_STRETCH`, half-size Win32 window) → `Present(0)`. | `src/native.rs` |
| Measurement | Topmost overlay at (0,0) painting the epoch-ms time as text plus a 40-cell barcode (2 markers, 32 bits, 6-bit popcount checksum), painted ~4 ms before each DWM composition. The browser and the native viewer decode the barcode from the decoded picture. Host stage timings use QPC. CPU and GPU-engine usage come from `tools/usage.ps1` (process CPU time, `\GPU Engine(*)\Utilization Percentage` per PID). | `src/overlay.rs`, `src/stats.rs`, `tools/` |

### Crates (all MIT / Apache-2.0 / BSD; no RustDesk code was used or consulted)

| Crate | Version | License | Use |
|---|---|---|---|
| `windows` / `windows-core` | 0.62.2 | MIT OR Apache-2.0 | DXGI, D3D11, Media Foundation, Win32, DWM |
| `str0m` | 0.25.0 | MIT OR Apache-2.0 | WebRTC (ICE, DTLS, SRTP, SCTP, RTP/H.264 packetizer) |
| ↳ `str0m-wincrypto` | 0.9.0 | MIT OR Apache-2.0 | crypto backend via Windows CNG: no OpenSSL, CMake or NASM needed (`default-features = false, features = ["wincrypto"]`) |
| ↳ `is` / `str0m-proto` / `dimpl` / `sctp-proto` | 0.12.0 / 0.8.0 / 0.9.0 / 0.10.8 | MIT OR Apache-2.0 | ICE agent / shared types / DTLS / SCTP |
| `tiny_http` | 0.12.0 | MIT OR Apache-2.0 | test-page HTTP server |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | signalling and stats JSON |

`cargo metadata` lists 76 packages across all targets: 54 "MIT OR Apache-2.0", 8 MIT,
5 "Apache-2.0 OR MIT", 2 Apache-with-LLVM-exception/MIT, 2 BSD-2/Apache/MIT, 1 BSD-3-Clause,
1 Unlicense/MIT, 1 MIT/Apache + Unicode-3.0. The only GPL mention is `r-efi` ("MIT OR Apache-2.0
OR LGPL-2.1-or-later", so MIT can be chosen), and it is a UEFI-only dependency that isn't compiled for Windows.
Toolchain: rustc 1.91.1 stable MSVC, VS 2022 build tools. Nothing was installed.

## Problems hit (and what they mean for the product)

1. **`AcquireNextFrame` blocking starves the encoder (biggest finding).** At first the AMD MFT
   showed 14–25 ms "encode" and only ~45 fps with dropped frames. An event trace (`MOON_ENC_TRACE=1`)
   showed `ProcessInput` itself blocking until the next vsync. MF needs the D3D11 device to be
   multithread-protected, and `IDXGIOutputDuplication::AcquireNextFrame(timeout>0)` holds that
   device lock while it waits for the next DWM frame. Fix: poll `AcquireNextFrame(0)` with a 1 ms
   sleep. Encode dropped to ~5 ms at a steady 60 fps with zero drops. Product: either keep the
   0-timeout poll, or give capture and encode separate devices with shared (keyed-mutex /
   NT-handle) textures. The second is cleaner and is also needed if the encoder ever moves to
   another process.
2. **The Microsoft H.264 decoder MFT holds one picture back.** This happens even with
   `MF_LOW_LATENCY`, `ICodecAPI AVLowLatencyMode=1` (accepted) and an SPS with
   `max_num_reorder_frames=0` (checked by parsing AMD's SPS). The decoder only finishes a picture
   when it sees the start of the next access unit. Fix: move the access-unit delimiter NAL from the
   front of each AU to its **end**. Native paint→glass fell from ~38 ms to ~21 ms at 60 fps
   (−1 frame). The decoder's output timestamps then shift by one input, so a pts-based lag counter
   reads 1 frame while the measured latency is correct.
3. **Pacing below the display rate.** Arrival-gap pacing (`skip if Δt < 0.8·interval`) gave
   ~21 fps instead of 30 and could drop the final change on a static screen. A first fixed-cadence
   version drifted against vsync, adding ~8 ms of slot wait. The final version always keeps the
   newest image, lets a *fresh* image use its slot up to ¼ interval early, re-anchors on each send,
   and sends a held-back image only once its slot is fully due.
4. **str0m did not report ICE `Disconnected`** after the browser tab was closed (still "connected"
   after more than 60 s, still sending 12 Mbit/s to a dead port). The spike now ends a session on
   data-channel close or after 5 s with no inbound UDP. The product needs its own liveness rule
   (RTCP / consent freshness), or should check whether a newer str0m handles this.
5. **Desktop "access lost"** (`DXGI_ERROR_ACCESS_LOST`) happened twice during runs (desktop
   switches: UAC/secure desktop or a mode change). Re-duplicating after 100 ms recovered within a
   second. The product will need a service-side capture path for the secure desktop (UAC,
   lock screen). That is a known Desktop Duplication limitation for a user-session process.
6. **Measurement pitfalls:** Chromium stops rendering occluded windows (rVFC fell to 0–3 fps while
   decode stayed at 60). The test Edge is launched with occlusion/backgrounding throttles off, and
   the native window is topmost. A parallel `cargo build` visibly degraded a run (p95 +20 ms), so
   that run was redone with the machine idle. `getStats().decoderImplementation` /
   `powerEfficientDecoder` are hidden by Chromium without a capture permission, so the browser's
   decoder implementation isn't reported. The ~0.2–0.7 ms `decodeMs` suggests hardware decode.
7. The mouse cursor isn't composited into the video (Desktop Duplication delivers the pointer
   shape separately). Expected; the product draws the cursor client-side or blends it on the GPU.
8. Encoder input textures are reused from an 8-deep ring without tracking when the async MFT
   releases them. That is fine at ≤2 frames in flight, but the product should use
   `IMFTrackedSample` or a fence before reusing a texture.

## Native viewer path (assessment)

Verdict: **viable, and the faster path.** Decoding the same Annex-B access units with the
Microsoft H.264 decoder MFT in D3D11 mode on a *separate* D3D11 device worked first time with
DXVA (`MF_SA_D3D11_AWARE=1`). The output is NV12 slices of a decoder texture array (one
`IMFDXGIBuffer` per sample). One `VideoProcessorBlt` converts NV12 → BGRA straight into the
swap chain's back buffer: no shaders, no CPU copies.

* Latency: paint→glass p50 **21 ms** with no other encoder on the GPU, 28–29 ms with RustDesk also
  encoding. That is 7–23 ms better than Chromium (which adds ≈ 24 ms between RTP receive and
  expected display at 60 fps). The `ProcessInput`/`ProcessOutput` CPU cost is 0.2 ms per frame.
* Required fix: the decoder holds one picture until it sees the next AU. Moving the AUD to the
  end of each access unit removed that frame (~17 ms at 60 fps). Setting the low-latency flags
  alone did not.
* Present path: flip-discard, 2 buffers, `DXGI_SCALING_STRETCH` (the swap chain stays 1920×1080
  while the window is half size), `Present(0)`. For the product: use a waitable swap chain
  (`DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT`, max latency 1). Also consider
  composition swap chains / DirectComposition in the Avalonia `NativeControlHost` HWND, and
  PresentMon to check whether independent flip is reached when the viewer is fullscreen. That
  would save the extra DWM frame which both viewers currently pay.
* The same code path is what the C# Lumen/Avalonia host would call through the Rust cdylib. It
  only needs an HWND (for `CreateSwapChainForHwnd`) and a feed of access units (from quinn/QUIC
  in the product).


## Go/no-go

**GO** for the decided stack (windows-rs DXGI capture → MF hardware H.264 → str0m WebRTC to
browsers; MF D3D11 decode → swap chain for the native viewer).

* The < 60 ms target is met at 1080p60 to the browser at p50 *and* p95 (35 / 48 ms), even while
  another remote-desktop app was encoding the same screen. The host pipeline itself costs only
  ~8 ms (present → bitstream on the wire) and < 1 % of the machine's CPU. Most of the remaining
  budget is the browser's own render pipeline, which we can't control. The native viewer
  reaches ~21 ms.
* 1080p30 meets the target on the median (52 ms) but not on p95 (64 ms). At 30 fps on a 60 Hz
  desktop each frame can wait up to one 33 ms slot. **Default to 60 fps** when the link allows:
  it costs +4 Mbit/s (12 vs 8) and ~6 % more video-codec engine for the host.
* Every crate needed is MIT/Apache. str0m's `wincrypto` backend avoids the OpenSSL/CMake/NASM
  build pain. Nothing had to be installed.

Conditions and open items before Phase 1:
1. Capture/encode device sharing: keep the 0-timeout duplication poll, or (preferred) give capture
   and encode separate D3D11 devices with keyed-mutex shared NV12 textures. Track input-texture
   release (`IMFTrackedSample`) instead of relying on ring depth.
2. Session liveness: add our own consent/RTCP timeout on top of str0m (it did not report a
   closed peer).
3. Secure desktop (UAC / lock screen) needs a SYSTEM-service capture path. `ACCESS_LOST` was
   seen and recovered in user mode.
4. Cursor: send the pointer shape and position separately (duplication already provides them) and
   draw on the client.
5. Not covered here: a real two-machine LAN (the clock-offset logic is in place but untested
   across machines), packet loss / congestion (no BWE, no NACK/FEC tuning; str0m supports
   NACK/TWCC), Intel/NVIDIA MFTs (only AMD VCN was tested), HDR/10-bit desktops, multiple
   monitors, rotated displays, and > 60 Hz displays.
6. Pacing at 30 fps: hold a stale frame for up to ~4 ms waiting for a fresh one instead of sending
   it exactly on its slot (the 30 fps present→bitstream average is 12 ms vs 8 ms at 60 fps).

### Reproduce

```powershell
cd spikes\media
cargo build --release
powershell -File tools\measure.ps1 -Fps 60 -Label 1080p60              # browser run (isolated Edge profile)
powershell -File tools\measure.ps1 -Fps 60 -Label native-1080p60 -Native -NoBrowser
python tools\summarize.py
```

`MOON_ENC_TRACE=1` prints an encoder event timeline (`I`/`i` ProcessInput begin/end, `N`
NeedInput, `H` HaveOutput, `O` output pulled). `MOON_DUMP_KEY=<file>` writes the first keyframe.

