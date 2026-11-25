import "./style.css";
import { WebSession, completeSignInIfCallback, signOut, startSignIn } from "./sso";
import { showSession } from "./viewer-session";

interface DeviceItem {
  id: string;
  name: string;
  kind: string;
  publicKey: string;
  online: boolean;
}

const WINDOWS_APP_DOWNLOAD =
  "https://release.moonl.cloud/v1/apps/moon-remote/windows-x64-setup/latest/download";
const WINDOWS_HOST_DOWNLOAD =
  "https://release.moonl.cloud/v1/apps/moon-remote/windows-x64-host/latest/download";
const RELEASE_PAGE = "https://release.moonl.cloud/apps/moon-remote";

let session: WebSession | null = null;
let devices: DeviceItem[] = [];
let statusText = "";
let showShareGuide = false;

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  if (!session) throw new Error("Not signed in");
  const resp = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.accessToken}`,
      ...(init?.headers ?? {}),
    },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return (await resp.json()) as T;
}

async function refreshDevices(): Promise<void> {
  const data = await api<{ devices: DeviceItem[] }>("/v1/devices");
  devices = data.devices.filter(d => d.kind === "host");
  statusText = `${devices.length} device(s), ${devices.filter((d) => d.online).length} online.`;
  render();
}

function renderStatus(): void {
  const el = document.getElementById("status-line");
  if (el) el.textContent = statusText;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]!));
}

function render(): void {
  const app = document.getElementById("app")!;
  app.innerHTML = `
    <header>
      <strong>Moon Remote Desktop</strong>
      <div class="row">
        <button id="btn-share-host" class="ghost">共享我的主机</button>
        <a class="btn ghost" href="${RELEASE_PAGE}" target="_blank" rel="noopener">下载客户端</a>
        ${
          session
            ? `<span>${escapeHtml(session.displayName)}</span><button id="btn-signout" class="ghost">退出</button>`
            : `<button id="btn-signin">使用 Moon SSO 登录</button>`
        }
      </div>
    </header>
    <main>
      <div id="status-line" style="color: var(--muted)">${escapeHtml(statusText)}</div>
      ${
        showShareGuide
          ? `<div class="card" style="border-color: rgba(59,130,246,0.5)">
              <div class="row" style="margin-bottom:8px">
                <strong>共享我的主机（轻量被控端插件）</strong>
                <button id="btn-close-share" class="ghost">收起</button>
              </div>
              <p style="color:var(--muted);margin-top:0">
                轻量 Core 被控端，支持开机后台运行，并在启动时自动检查更新。
              </p>
              <ol style="color:#cbd5e1;line-height:1.9;padding-left:20px;margin:12px 0">
                <li>下载轻量被控端压缩包并解压到任意目录（例如 <code>C:\\MoonRemoteHost</code>）。</li>
                <li>双击运行 <code>moonrd-host.exe</code>，在自动打开的本机向导中登录 Moon 账号、设置 6–12 位连接 PIN，保持勾选「开机自动启动」。</li>
                <li>完成后关闭向导窗口，回到此页面点击「刷新」即可看到该主机在线并远程连接。</li>
              </ol>
              <div class="row" style="justify-content:flex-start;margin-top:14px">
                <a class="btn" href="${WINDOWS_HOST_DOWNLOAD}">下载 Core 被控端 (Windows x64)</a>
                <a class="btn ghost" href="${WINDOWS_APP_DOWNLOAD}">下载桌面安装器 (控制+被控)</a>
              </div>
            </div>`
          : ""
      }
      ${
        session
          ? `<div class="card">
              <div class="row" style="margin-bottom:12px">
                <strong>Your Devices</strong>
                <button id="btn-refresh" class="ghost">Refresh</button>
              </div>
              <div id="device-list">
                ${
                  devices.length === 0
                    ? `<p style="color:var(--muted)">No devices registered yet. Install Moon Remote on Windows to enable host access.</p>`
                    : devices
                        .map(
                          (d) => `<div class="device-item">
                            <div>
                              <div><strong>${escapeHtml(d.name)}</strong></div>
                              <div style="font-size:12px;color:var(--muted)">${escapeHtml(d.id)}</div>
                            </div>
                            <div class="row">
                              <span class="badge ${d.online ? "online" : ""}">${d.online ? "Online" : "Offline"}</span>
                              <button data-connect="${escapeHtml(d.id)}" ${d.online ? "" : "disabled"}>Connect</button>
                            </div>
                          </div>`
                        )
                        .join("")
                }
              </div>
            </div>
            <div class="card">
              <strong>Remote Support</strong>
              <p style="color:var(--muted)">Enter a 12-digit one-time support code to assist another computer.</p>
              <div class="row" style="justify-content:flex-start">
                <input id="support-code" placeholder="0000 0000 0000" maxlength="16" />
                <button id="btn-redeem">Connect</button>
              </div>
            </div>`
          : `<div class="card">
              <h2>Control your Windows PCs from any browser</h2>
              <p style="color:var(--muted)">End-to-end SPAKE2 PIN verification bound to WebRTC DTLS. Sign in with your Moon account to get started, or download the Windows app to share this PC.</p>
              <div class="row" style="justify-content:flex-start;margin-top:16px">
                <button id="btn-signin-hero">使用 Moon SSO 登录</button>
                <button id="btn-share-hero" class="ghost">共享我的主机</button>
                <a class="btn ghost" href="${WINDOWS_APP_DOWNLOAD}">下载 Windows 安装器</a>
              </div>
            </div>`
      }
    </main>
  `;

  document.getElementById("btn-signin")?.addEventListener("click", () => void startSignIn());
  document.getElementById("btn-signin-hero")?.addEventListener("click", () => void startSignIn());
  document.getElementById("btn-share-host")?.addEventListener("click", () => {
    showShareGuide = !showShareGuide;
    render();
  });
  document.getElementById("btn-share-hero")?.addEventListener("click", () => {
    showShareGuide = true;
    render();
  });
  document.getElementById("btn-close-share")?.addEventListener("click", () => {
    showShareGuide = false;
    render();
  });
  document.getElementById("btn-signout")?.addEventListener("click", () => {
    signOut();
    session = null;
    devices = [];
    render();
  });
  document.getElementById("btn-refresh")?.addEventListener("click", () => void refreshDevices());

  document.querySelectorAll<HTMLButtonElement>("button[data-connect]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const dev = devices.find((d) => d.id === btn.dataset.connect);
      if (dev) showSession(dev, api);
    });
  });
  document.getElementById("btn-redeem")?.addEventListener("click", async () => {
    const input = document.getElementById("support-code") as HTMLInputElement;
    const code = input.value.replace(/\D/g, "");
    if (code.length !== 12) {
      statusText = "Support code must be 12 digits.";
      renderStatus();
      return;
    }
    try {
      const res = await api<{ session: string; hostName: string }>("/v1/support/redeem", {
        method: "POST",
        body: JSON.stringify({ code }),
      });
      statusText = `Redeemed support session ${res.session} (${res.hostName}).`;
      renderStatus();
    } catch (err) {
      statusText = `Redeem failed: ${String(err)}`;
      renderStatus();
    }
  });
}

async function boot(): Promise<void> {
  try {
    session = await completeSignInIfCallback();
    if (session) await refreshDevices();
  } catch (err) {
    statusText = `Sign-in error: ${String(err)}`;
  }
  render();
}

void boot();
