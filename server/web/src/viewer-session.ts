import protobuf from "protobufjs";
import schema from "../../../proto/moonrd.proto?raw";
import { AuthMethod, derivePinSecret, Pake, type PakeKeys } from "./pake";
import { WebRtcViewer, type TurnConfig } from "./webrtc";

const envelope = protobuf.parse(schema).root.lookupType("moonrd.v1.Envelope");
type Api = <T>(path: string, init?: RequestInit) => Promise<T>;
const keys: Record<string, number> = { Enter:40, Escape:41, Backspace:42, Tab:43, Space:44, Minus:45, Equal:46,
  BracketLeft:47, BracketRight:48, Backslash:49, Semicolon:51, Quote:52, Backquote:53, Comma:54, Period:55, Slash:56,
  CapsLock:57, Insert:73, Home:74, PageUp:75, Delete:76, End:77, PageDown:78, ArrowRight:79, ArrowLeft:80, ArrowDown:81, ArrowUp:82,
  ControlLeft:224, ShiftLeft:225, AltLeft:226, MetaLeft:227, ControlRight:228, ShiftRight:229, AltRight:230, MetaRight:231 };
function hid(code: string) {
  if (/^Key[A-Z]$/.test(code)) return code.charCodeAt(3) - 65 + 4;
  if (/^Digit[0-9]$/.test(code)) return (Number(code[5]) + 9) % 10 + 30;
  if (/^F([1-9]|1[0-2])$/.test(code)) return 57 + Number(code.slice(1));
  return keys[code];
}

export function videoPoint(x: number, y: number, w: number, h: number, vw: number, vh: number, clamp: boolean) {
  if (Math.min(w,h,vw,vh) <= 0) return null;
  const scale = Math.min(w/vw,h/vh);
  const px = (x-(w-vw*scale)/2)/(vw*scale), py = (y-(h-vh*scale)/2)/(vh*scale);
  if (!clamp && (px < 0 || py < 0 || px > 1 || py > 1)) return null;
  const norm = (v: number) => Math.round(Math.max(0,Math.min(1,v))*65535);
  return { x: norm(px), y: norm(py) };
}

export function showSession(dev: {id:string;name:string}, api: Api): void {
  const dlg = document.createElement("dialog");
  dlg.className = "session";
  dlg.innerHTML = `<section><div class="row"><strong></strong><div class="row"><button class="ghost" data-type disabled title="使用本机输入法（Ctrl+Shift+Enter）">发送文字</button><button class="ghost" data-full>全屏</button>
    <button class="ghost" data-close>关闭</button></div></div><p role="status"></p>
    <form data-pin><label>主机 PIN <input type="password" inputmode="numeric" pattern="[0-9]{6,12}" minlength="6" maxlength="12" required autofocus></label>
    <button type="submit">连接</button></form>
    <video autoplay playsinline muted tabindex="0" hidden></video>
    <dialog class="send-text-dialog" aria-label="发送文字">
      <form data-text>
        <label>发送文字<input type="text" maxlength="1024" autocomplete="off" placeholder="使用本机输入法" autofocus></label>
        <span role="status" data-text-error hidden></span>
        <div class="text-actions"><button type="button" class="ghost" data-cancel-text>取消</button>
          <button type="button" data-send-text disabled>发送 · Enter</button></div>
      </form>
    </dialog></section>`;
  document.body.append(dlg);
  const video = dlg.querySelector("video")!, status = dlg.querySelector("p")!;
  const form = dlg.querySelector<HTMLFormElement>("[data-pin]")!, pinInput = form.querySelector("input")!;
  const textDialog = dlg.querySelector<HTMLDialogElement>(".send-text-dialog")!;
  const textForm = dlg.querySelector<HTMLFormElement>("[data-text]")!, textInput = textForm.querySelector("input")!;
  const textError = textForm.querySelector<HTMLElement>("[data-text-error]")!, typeButton = dlg.querySelector<HTMLButtonElement>("[data-type]")!;
  const sendButton = textForm.querySelector<HTMLButtonElement>("[data-send-text]")!;
  const full = dlg.querySelector<HTMLButtonElement>("[data-full]")!;
  dlg.querySelector("strong")!.textContent = dev.name;
  dlg.showModal();
  let viewer: WebRtcViewer | null = null, ws: WebSocket | null = null, ready = false, displayId = 1;
  let generation = 0, timer = 0;
  let composing = false;
  const held = new Set<number>(), buttons = new Set<number>();
  let last = {x:0,y:0};
  const send = (data: object) => viewer?.sendControl(envelope.encodeDelimited(envelope.create(data)).finish()) ?? false;
  function releaseButtons() {
    if (ready) for (const button of buttons) send({pointer:{displayId,...last,button,pressed:false}});
    buttons.clear();
  }
  function release() {
    if (ready) for (const scancode of held) send({key:{scancode,pressed:false}});
    held.clear(); releaseButtons();
  }
  function openText() {
    if (!ready || textDialog.open) return;
    release();
    textDialog.showModal();
    textInput.focus();
  }
  textDialog.onclose = () => {
    composing = false; textInput.value = ""; sendButton.disabled = true; textError.hidden = true;
    if (ready) video.focus();
  };
  dlg.addEventListener("keydown", e => {
    if (textDialog.open || !ready || e.code !== "Enter" || !e.ctrlKey || !e.shiftKey || e.altKey || e.metaKey) return;
    e.preventDefault();
    e.stopPropagation();
    if (!e.repeat) openText();
  }, true);
  function stop(message: string) {
    generation++;
    release(); ready = false; clearTimeout(timer); ws?.close(); ws = null; viewer?.close(); viewer = null;
    typeButton.disabled = true; textDialog.close();
    video.srcObject = null; video.hidden = true; form.hidden = false; status.textContent = message;
  }
  const surface = dlg.querySelector("section")!;
  surface.className = "screen-surface";
  const fsChange = () => {
    const active = document.fullscreenElement === surface;
    full.textContent = active ? "退出全屏" : "全屏";
    if (active && ready && !textDialog.open) video.focus();
  };
  surface.onpointermove = e => {
    if (document.fullscreenElement === surface)
      surface.classList.toggle("show-controls", e.clientY < 48 && e.clientX > surface.clientWidth - 360);
  };
  document.addEventListener("fullscreenchange",fsChange);
  window.addEventListener("blur", release);
  full.disabled = !document.fullscreenEnabled;
  full.onclick = async () => {
    try { if (document.fullscreenElement === surface) await document.exitFullscreen(); else await surface.requestFullscreen(); }
    catch { status.textContent = "浏览器未允许全屏。"; }
  };
  dlg.querySelector<HTMLButtonElement>("[data-close]")!.onclick = () => dlg.close();
  textDialog.oncancel = e => { if (composing) e.preventDefault(); };
  dlg.onclose = () => {
    stop(""); document.removeEventListener("fullscreenchange",fsChange);
    window.removeEventListener("blur", release); dlg.remove();
  };
  typeButton.onclick = openText;
  textForm.querySelector<HTMLButtonElement>("[data-cancel-text]")!.onclick = () => textDialog.close();
  textInput.oninput = () => { sendButton.disabled = !textInput.value; };
  textInput.addEventListener("compositionstart", () => { composing = true; });
  textInput.addEventListener("compositionend", () => { composing = false; });
  // Submit from the key event rather than the implicit form action, which can be
  // triggered by Enter while an input method is still choosing a candidate.
  textForm.onsubmit = e => e.preventDefault();
  textInput.onkeydown = e => {
    if (e.key !== "Enter" || composing || e.isComposing || e.keyCode === 229) return;
    e.preventDefault();
    if (!e.repeat) sendText();
  };
  function sendText() {
    if (!textInput.value || composing) return;
    if (ready && send({key:{text:textInput.value}})) textDialog.close();
    else { textError.textContent = "发送失败，请重试。"; textError.hidden = false; }
  }
  sendButton.onclick = sendText;
  video.onblur = release;
  video.oncontextmenu = e => e.preventDefault();
  function pointer(e: PointerEvent | WheelEvent, button = 0, pressed = false, wheelX = 0, wheelY = 0) {
    if (!ready) return false;
    const r = video.getBoundingClientRect();
    const p = videoPoint(e.clientX-r.left,e.clientY-r.top,r.width,r.height,video.videoWidth,video.videoHeight,buttons.size>0);
    if (!p) return false;
    last = p; send({pointer:{displayId,...p,button,pressed,wheelX,wheelY}}); return true;
  }
  const buttonMap = [1,3,2,4,5];
  video.onpointerdown = e => {
    const b = buttonMap[e.button];
    if (b && pointer(e,b,true)) { buttons.add(b); video.focus(); video.setPointerCapture(e.pointerId); e.preventDefault(); }
  };
  video.onpointerup = e => { const b = buttonMap[e.button]; if (buttons.has(b)) { pointer(e,b,false); buttons.delete(b); } };
  video.onpointermove = e => { pointer(e); };
  video.onlostpointercapture = releaseButtons;
  video.onwheel = e => { if (pointer(e,0,false,Math.sign(e.deltaX)*120,-Math.sign(e.deltaY)*120)) e.preventDefault(); };
  function key(e: KeyboardEvent, pressed: boolean) {
    const code = hid(e.code);
    if (!ready || !code || (e.code === "Escape" && document.fullscreenElement)) return;
    e.preventDefault();
    if (!pressed && !held.has(code)) return;
    if (!send({key:{scancode:code,pressed}})) return;
    if (pressed) held.add(code); else held.delete(code);
  }
  video.onkeydown = e => key(e,true); video.onkeyup = e => key(e,false);
  form.onsubmit = async e => {
    e.preventDefault();
    let pin = pinInput.value; pinInput.value = ""; form.hidden = true;
    const id = ++generation, session = crypto.randomUUID();
    const current = () => generation === id && dlg.open;
    const fail = (err: unknown) => { if (current()) stop(String(err)); };
    const sendAuth = (data: object) => { if (!send(data)) throw Error("认证消息发送失败。"); };
    status.textContent = "正在连接主机…";
    timer = window.setTimeout(() => fail("主机连接超时，请检查网络和被控端版本后重试。"),45000);
    try {
      const [turn, ticket] = await Promise.all([api<TurnConfig>("/v1/turn"), api<{ticket:string}>("/v1/signal/ticket",{method:"POST"})]);
      if (!current()) return;
      const rtc = new WebRtcViewer(turn.iceServers); viewer = rtc;
      let binding: Uint8Array, pake: Pake | null = null, proof: PakeKeys | null = null, verified = false;
      rtc.onTrack = stream => { if (current()) video.srcObject = stream; };
      rtc.onDataOpen = b => {
        if (!current()) return;
        binding = b;
        try { sendAuth({hello:{protocolVersion:1,kind:1,viewerDisplayName:"Web",clientVersion:"web",codecs:[1],authMethods:[1]}}); }
        catch (err) { fail(err); }
      };
      rtc.onDataMessage = data => {
        if (!current()) return;
        try {
          const msg = envelope.toObject(envelope.decodeDelimited(data));
          if (msg.helloAck) {
            const ack = msg.helloAck;
            if (ack.hostDeviceId !== dev.id || ack.authMethod !== 1 || !pin || !ack.argon2 || ack.argon2.memoryKib > 65536 ||
              ack.argon2.iterations > 8 || ack.argon2.parallelism > 8) throw Error("主机认证参数无效");
            const secret = derivePinSecret(pin,ack.pinSalt,ack.argon2); pin = "";
            const auth = Pake.start("viewer",AuthMethod.Pin,secret,binding); pake = auth.pake;
            sendAuth({auth:{spake2Message:auth.message}});
          } else if (msg.auth?.spake2Message && pake) {
            proof = pake.finish(msg.auth.spake2Message); pake = null; sendAuth({auth:{keyConfirmation:proof.confirmation}});
          } else if (msg.auth?.keyConfirmation && proof) {
            verified = proof.verifyPeer(msg.auth.keyConfirmation); proof = null;
          } else if (msg.authResult) {
            if (msg.authResult.status !== 1 || !verified) throw Error(msg.authResult.lockoutSeconds ?
              `PIN 已锁定，请在 ${msg.authResult.lockoutSeconds} 秒后重试。` : "PIN 验证失败。");
            ready = true; typeButton.disabled = false; status.textContent = "已验证，正在等待画面…"; video.hidden = false; video.focus();
            void video.play().catch(fail);
          } else if (msg.displayList?.activeId) displayId = msg.displayList.activeId;
        } catch (err) { fail(err); }
      };
      video.onplaying = () => { if (current() && ready) { clearTimeout(timer); status.textContent = `已连接 · ${video.videoWidth} × ${video.videoHeight}`; } };
      rtc.onStateChange = state => { if (state === "failed" || state === "closed") fail("远程连接已断开。"); };
      const url = new URL("/v1/signal",location.href); url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
      url.searchParams.set("ticket",ticket.ticket);
      const socket = new WebSocket(url); ws = socket;
      socket.onerror = () => fail("信令连接失败。");
      socket.onclose = () => { if (!ready) fail("信令连接已关闭。"); };
      socket.onopen = async () => {
        try { const offer = await rtc.createOffer(); if (current()) socket.send(JSON.stringify({type:"invite",to:dev.id,session,data:{transport:"webrtc",sdp:offer.sdp}})); }
        catch (err) { fail(err); }
      };
      socket.onmessage = async e => {
        try {
          const msg = JSON.parse(String(e.data)); if (!current() || msg.session !== session) return;
          if (msg.type === "error") throw Error(msg.code);
          if (msg.from !== dev.id) return;
          if (msg.type === "sdp") await rtc.setAnswer(msg.data);
          if (msg.type === "reject") throw Error(msg.data?.reason ?? "主机拒绝连接。");
          if (msg.type === "quic-endpoint") throw Error("请在被控电脑上更新 Moon Remote 安装器后重试网页连接。");
        } catch (err) { fail(err); }
      };
    } catch (err) { fail(err); }
  };
}
