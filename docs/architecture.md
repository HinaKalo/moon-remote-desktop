# Moon Remote Desktop — 架构与实施计划

## Context

`C:\develop\moon-remote-desktop` 目前是空目录，要从零做一个类似 Chrome Remote Desktop 的远程控制产品：
- Windows 桌面端（控制端 + 被控端合一），UI 用 Lumen.UI（`dotnet new lumen-app`）；
- 网页版控制端 remote.moonl.cloud（WebRTC），页面提供 Windows 版下载；
- 账号走 sso.moonl.cloud，连接被控端时再用**每台主机的 PIN** 做二次验证（CRD 式，端到端 PAKE，服务器看不到 PIN）；
- 同账号设备之间走 EasyTier 虚拟网（伴生 easytier-core，RPC 控制），EasyTier 凭据由服务器单一签发，客户端不内置任何网络密钥；
- 兼容用户自己装的 EasyTier；
- 产物发布到 release.moonl.cloud。

已定决策（用户确认）：媒体核心用 **Rust**、UI 用 **C# Lumen**；PIN = **每台被控端的连接 PIN**；首版含**自有设备无人值守**和**一次性协助码**；平台**仅 Windows x64**（任意浏览器可作网页控制端）。

可复用的现有资产（Explore 已核实）：
- `C:\develop\moon-sso\sdk\dotnet`（MoonSso.Client / MoonSso.Desktop）：PKCE + 127.0.0.1 回环、DPAPI 存会话、自动刷新、`MoonSsoAuthHandler`；README 有 Avalonia 示例。默认对公共客户端启用 DPoP（资源服务器要验 DPoP）。TS SDK 用于网页端，Go SDK 可参考。
- `C:\develop\moon-sso\server`：Go 1.27 + Echo v5 + MySQL + Caddy（moon 主机）、`deploy\deploy.ps1` 的 staging→prod 流程 —— 新服务照搬这套栈和部署方式。
- `C:\develop\night-clip\windows\ClipBridge.Windows`：唯一的 Lumen 实战应用。复用其模式：`Services\SingleInstance.cs`、`TrayService.cs`、`AutoStartRegistry.cs`、`DpapiProtector.cs`、`Update\UpdateApplier.cs`/`BuildInfo.cs`、`Interop\`（C ABI：init / call(JSON) / next_event 三函数模型）。
- relhub：`night-clip\docs\release-publish-integration.md` §8 新应用接入清单、`scripts\release-local.sh`；Ed25519 签名清单，公钥见 `night-clip\core\update\keys.go`。
- lumen-ui skill 的坑列表（DialogHost 宽度/点遮罩、默认英文文案、NavItem 不通知等）。

不复制 RustDesk 代码（AGPL-3.0），只借鉴架构（DXGI 采集、服务进程进会话、SendInput、协议分层）。

## 总体架构

```
                    ┌──────────── remote.moonl.cloud (moon, Caddy) ────────────┐
                    │ moon-remote-server (Go/Echo/MySQL)                        │
 sso.moonl.cloud ◄──┤  • REST: 设备/主机注册、协助码、ET 凭据、TURN 凭据         │
  (JWKS + DPoP)     │  • WSS 信令: 在线状态、会话邀约、SDP/ICE、QUIC 端点+指纹   │
                    │  • ET 管理器: 每用户一个 EasyTier 网络，服务端节点持 secret │
                    │    签发短期 credential；同时充当公共 peer/中继            │
                    │  • 静态托管网页控制端 (TS SPA) + 下载链接                  │
                    └───────┬──────────────────────┬───────────────┬───────────┘
                            │ coturn (TURN/TLS 443) │ easytier-core │ release.moonl.cloud
 ┌──── Windows 客户端 ───────┴──────────────────────┴───────────────┴──────────┐
 │ MoonRemote.exe (C# Lumen UI, 每用户)                                        │
 │   └─ moonrd_ffi.dll (Rust cdylib, 进程内)：控制端会话、解码、D3D11 渲染到   │
 │        NativeControlHost 的 HWND；无服务时自带 no-TUN easytier-core 伴生     │
 │   ⇅ 命名管道 JSON-RPC (\\.\pipe\moonrd-service, ACL 限交互用户)              │
 │ moonrd-service.exe (Rust, Windows 服务 LocalSystem)                         │
 │   • 设备凭据(DPAPI LocalMachine)、信令 WSS、PIN 校验状态与锁定               │
 │   • EtSupervisor：伴生 easytier-core(TUN)，RPC 控制、健康检查、重启          │
 │   • 用 SYSTEM 令牌把 moonrd-host 拉进活动控制台会话，跟随会话切换            │
 │ moonrd-host.exe (Rust, 活动会话内)：DXGI 采集 → MF 硬件 H.264 → 传输；        │
 │   SendInput / SendSAS / 剪贴板；切换到安全桌面(UAC/登录界面)                  │
 │ easytier-core.exe (固定版本, sha256 校验, LGPL 单独进程)                     │
 └────────────────────────────────────────────────────────────────────────────┘
 浏览器控制端：TS SPA + WebRTC（只做控制端，不能做被控端）
```

### 传输（会话层统一，传输两种）
- Rust `moonrd-session` 定义与传输无关的会话协议（protobuf，`proto/moonrd.proto`：Hello/Auth(PAKE)/VideoConfig/VideoFrame/Mouse/Key/Clipboard/Cursor/Display/Stats/KeyframeRequest…），抽象 `Channel`（可靠控制流 + 不可靠视频流）。
- **QuicChannel**（quinn）：同账号原生 ↔ 原生，跑在 EasyTier 上。TLS 1.3 用设备 Ed25519 密钥作 RFC 7250 原始公钥（不用 X.509 证书），按服务器设备列表逐字节比对（EasyTier 网络内其他成员也冒充不了）。
- **WebRtcChannel**（str0m）：浏览器控制端、跨账号协助会话（含原生控制端协助他人时）。H.264 RTP 视频轨 + DataChannel；ICE 用 STUN + coturn（短期 REST 凭据，TLS 443）。
- 编码：DXGI Desktop Duplication（windows-rs，GDI 兜底）→ Media Foundation 硬件 H.264 MFT（覆盖 NVENC/QSV/AMF），低延迟配置（无 B 帧、按需 IDR）；软件兜底 OpenH264。原生端 MF D3D11 解码 + D3D11 swapchain；浏览器原生解码。

### EasyTier（需求 2、8、9）

> Phase 0a 结论已落地（`spikes/easytier/REPORT.md`）：固定 **v2.7.1**；主机和控制端**都不用 TUN**（无需管理员，主机 QUIC 监听 127.0.0.1）；设备用可写 TOML（`-c`）启动，凭据写在 `[secure_mode] local_private_key`（`--credential-file` 是管理端存储，不是设备参数）；服务端每个账号网络一个 easytier-core、一个公网端口；每台设备最多保留两张凭据，续期换新 ID；不分发 Npcap 的 `Packet.dll`，用 `core/crates/packet-stub` 的空实现替代（`scripts/fetch-easytier.ps1`）。下文中与此冲突的旧描述以此为准。
- **封装**：Rust crate `moonrd-et` = EtSupervisor。启动固定版本 easytier-core（或 easytier-mini，Phase 0 比选），控制面用其管理端口 RPC（先走 `easytier-cli --output json -p <port>`，稳定后可换 easytier-ffi 的 `call_json_rpc`）；监控 ListPeer/ShowNodeInfo，崩溃退避重启，随宿主进程退出（Job Object kill-on-close）。
- **单一信源签发**：moon-remote-server 为每个 SSO 用户生成网络（`mrd-<uid 哈希>`，secret 仅存服务器 DB 加密列），服务端为活跃网络运行一个持 secret 的 easytier-core 节点（同时是公共 peer），通过 `CredentialManageRpc.GenerateCredential(ttl=24h, groups, allow_relay=true)` 给每台设备签发短期 credential；客户端只拿到 `{network_name, credential_secret, expiry, peers, cidr}`，以 `--credential-file`（临时文件、严格 ACL、启动后删除）传入，不出现在命令行；设备删除/登出时 `RevokeCredential` 全网踢出；到期前由服务/控制端续签。
- **与用户自装 EasyTier 共存**：
  - 检测：SCM 中 `EasyTierService`/`easytier` 或可执行名为 easytier-core 的服务；进程 easytier-core/easytier-gui；127.0.0.1:15888 与 11010 占用；`et_*` 网卡；若其 RPC 可读，读取其虚拟网段。
  - 隔离：自带二进制放 `%ProgramFiles%\MoonRemote\easytier\`；`--instance-name moonrd`、`--dev-name moonrd0`、`--rpc-portal 127.0.0.1:<随机空闲端口>` + `--rpc-portal-whitelist 127.0.0.1/32`、`--no-listener`（只出站）；虚拟网段由服务器从 10.250.0.0/16 分配 /24，客户端上报本机已占网段，冲突则换段；绝不修改用户自己的服务、配置、防火墙规则。
  - 设置页提供“使用自定义 easytier-core 路径”（校验最低版本），并在诊断页展示检测到的外部 EasyTier。
- 被控端（服务，有管理员权限）用 TUN，QUIC 监听虚拟 IP；纯控制端（未装服务、无管理员）用 `--no-tun`，按会话通过 PortForwardManageRpc 动态添加 `udp://127.0.0.1:<p> → 主机虚拟IP:端口`。

### 身份与认证
- 用户：MoonSso.Desktop（PKCE 回环）登录；scope `openid profile offline_access`；服务器用 JWKS 验 JWT + DPoP。
- 设备：首次运行生成 Ed25519 设备密钥。启用“允许远程访问”时，UI 用用户令牌向服务器注册主机，服务器返回**设备令牌**（长期、可吊销，绑定设备公钥签名挑战），由服务以 DPAPI LocalMachine + ACL 文件保存 —— 无人登录时主机也在线（同 CRD 的主机机器人账号）。
- **主机 PIN**（≥6 位）：在主机本地设置，存 `w = Argon2id(PIN, host_salt)`（DPAPI LocalMachine）。连接时跑 **SPAKE2（Ed25519 群，RustCrypto spake2 0.4，详见 docs/protocol.md）**，transcript 绑定 QUIC TLS exporter / DTLS 指纹 → 信令服务器无法中间人；失败 5 次指数退避锁定并持久化；可选“记住此控制端”（配对密钥，跳过 PIN，可在主机端撤销）。浏览器端用 @noble/curves + argon2 wasm 实现同一 SPAKE2，必须通过跨语言测试向量。
- **一次性协助码**：被控方（无需安装服务、无需管理员，moonrd-host 直接在用户上下文运行）点“获取协助码” → 服务器发 12 位码（5 分钟、一次性）→ 协助方（任意 SSO 账号，桌面或网页）输入 → 被控方弹出显示对方 SSO 身份的确认框 → 走 WebRtcChannel；协助码同时作为 PAKE 口令；会话结束即失效，不可无人值守重连；无法操作 UAC 界面（UI 上说明）。

### 局域网直连回退（用户追加需求）
- 被控端设置项“允许局域网直连”，**默认关闭**；开启后 moonrd-service 额外在物理网卡上监听 QUIC（防火墙规则只放行“专用”网络配置文件），并通过 mDNS `_moonrd._udp.local` 广播（只含设备 ID 与显示名，可设为不广播、仅手动输入 IP）。
- 控制端：服务器或 EasyTier 不可用时，设备列表显示“局域网”标签并直接走 QuicChannel 连 LAN IP；也支持手动输入 `IP[:端口]`。服务器可用且同网段时，EasyTier 本身就会 P2P 直连，不必走这条路径。
- 离线认证（不依赖服务器）：
  - **PIN 始终必需**：SPAKE2 绑定 QUIC TLS exporter，局域网内的中间人不知道 PIN 就无法通过。
  - 账号绑定：在线时服务器给每台设备下发**服务器签名的同账号设备名册**（设备公钥列表，Ed25519 签名，离线有效期 14 天）。主机只接受名册内控制端设备密钥的局域网连接；名册过期或不在名册中则拒绝（可在主机端改为“仅凭 PIN 也允许”，默认关闭）。
  - 已配对的“记住此控制端”在局域网模式下同样有效，但仍受名册约束。
- 局域网模式不提供一次性协助码与网页控制端（这两者都需要服务器）。
- 测试：断开服务器（hosts 屏蔽 remote.moonl.cloud）后两台同网段机器仍能用 PIN 连接；名册过期后拒绝；公共网络配置文件下端口不开放。

### 服务器 `moon-remote-server`（Go，照搬 moon-sso 栈）
- `internal/auth`（SSO JWT+DPoP、设备令牌）、`devices`、`signal`（WSS hub：presence、invite、sdp/ice、quic-endpoint）、`et`（网络/节点生命周期、credential 签发与吊销、网段分配）、`turn`（coturn REST 共享密钥）、`support`（协助码）、`web`（嵌入 SPA）。
- 部署：moon 上 Caddy 反代 remote.moonl.cloud，staging/prod 双实例，`deploy\deploy.ps1` 同款流程；coturn 与 easytier-core 作为 systemd 服务；EasyTier 公共端口开在防火墙。
- 下载按钮：`https://release.moonl.cloud/v1/apps/moon-remote/windows-x64-setup/latest/download`。

### 发布（需求 7）
- relhub 新建 app `moon-remote`，两个平台：`windows-x64`（zip，自动更新用）与 `windows-x64-setup`（Inno Setup 安装器，网页下载用）；versionCode = `git rev-list --count HEAD`。
- 自动更新：C# 侧按 relhub `/check` + `/watch` 检查并验 Ed25519 清单（参照 ClipBridge 公钥/格式）；下载后交给 **moonrd-service**（SYSTEM）停服务→换文件→重启，失败回滚（移植 `UpdateApplier.cs` 的 staging/回滚逻辑）。
- 第三方许可：`THIRD_PARTY_NOTICES` 附 EasyTier(LGPL-3.0，单独进程、未修改、注明源码位置)、wintun、quinn/str0m/windows-rs 等；不捆绑 Npcap 的 Packet.dll（Phase 0 确认 EasyTier 包内 Packet.dll 来源，必要时不分发）。

## 仓库结构（新建）

```
moon-remote-desktop/
  proto/moonrd.proto                 会话协议（Rust/TS 共用）
  core/  (Cargo workspace)
    crates/moonrd-proto, moonrd-capture, moonrd-codec, moonrd-input,
           moonrd-transport (quic + webrtc), moonrd-session (协议+PAKE),
           moonrd-et (EtSupervisor), moonrd-ipc (命名管道 JSON-RPC)
    bins/moonrd-service, moonrd-host;  cdylib/moonrd-ffi
  app/   (dotnet new lumen-app -n MoonRemote)
    src/MoonRemote: Views(登录/设备列表/主机设置+PIN/控制窗口/协助/设置/诊断),
                    Services(Sso, ServicePipeClient, Update, Tray, SingleInstance, AutoStart),
                    Interop(moonrd_ffi: init/call/next_event)
    tests/MoonRemote.Tests (逻辑 + Avalonia.Headless 截图)
  server/ (Go module) cmd/moon-remote-server, internal/*, web/ (Vite + TS SPA)
  installer/MoonRemote.iss           安装/注册服务/防火墙规则
  scripts/ fetch-easytier.ps1(固定版本+sha256), build.ps1, release-local.ps1
  docs/  architecture.md, protocol.md, security.md, THIRD_PARTY_NOTICES
```

## 分阶段实施

0. **技术验证（先做，逐项 go/no-go）**
   a. EasyTier：固定版本（v2.7.x 是否必需、是否仍 pre-release）；服务端节点 GenerateCredential/Revoke 用 CLI JSON 跑通；被控 TUN + 控制端 no-TUN 端口转发 QUIC 互通；与已装 EasyTier（默认 15888/11010/et_0）同机并存；no-TUN 是否免管理员；core vs mini 比选。失败兜底：easytier-web 配置服务器 + webhook 校验 SSO 令牌下发配置。
   b. 媒体链路：DXGI → MF H.264 → str0m → Chrome 播放，测端到端延迟（目标局域网 <60ms）；同链路 quinn 原生端解码渲染。
   c. Go 服务验证 moon-sso 签发的 JWT + DPoP；确认需要在 SSO 开发者门户注册的客户端（桌面 native、网页 SPA）。
1. 脚手架：三套工程 + proto 生成 + `scripts/build.ps1` 一键构建。
2. 服务器：auth、devices、et 管理器、signal、turn；Go 单测 + staging 部署。
3. Rust 核心：capture/codec/input、QuicChannel、会话协议、SPAKE2 PIN + 锁定；EtSupervisor。
4. moonrd-service：服务安装、会话跟随（WTS 通知）、安全桌面、SendSAS、命名管道 API、设备令牌。
5. Lumen UI：登录、设备列表（在线状态）、主机设置/PIN、控制窗口（NativeControlHost + 全屏/多显示器/快捷键透传/剪贴板）、设置、诊断、托盘、自启。
6. WebRtcChannel + 网页控制端（SSO TS SDK 登录、设备列表、PIN、WebRTC 观看与输入、下载入口）。
7. 一次性协助码（桌面与网页两侧）；局域网直连回退（mDNS、签名名册、离线 PIN 认证）。
8. 安装器、自动更新、relhub 接入、文档与许可清单、发布 0.1.0。

## 验证

- 单测：`cargo test`（PAKE 往返、锁定、协议编解码、EtSupervisor 参数生成/外部 EasyTier 检测）、`go test ./...`（凭据签发/吊销、协助码过期/一次性、信令鉴权）、`dotnet test`（逻辑 + Lumen 亮/暗无头截图）。
- 跨语言：SPAKE2/Argon2 测试向量 Rust ⇄ TS 一致。
- 端到端（两台 Windows：本机 + KOEI，另一台预装 EasyTier GUI 运行中）：
  1) 账号登录 → 主机启用并设 PIN → 另一台控制，测延迟/重连、锁屏/UAC 下仍可操作、Ctrl+Alt+Del；
  2) 错 PIN 5 次触发锁定；删除设备后其 EasyTier credential 立即失效；
  3) 主机上用户自己的 EasyTier 网络与服务在测试前后均正常（端口、网卡、路由不变）；
  4) 内置浏览器打开 staging 的 remote.moonl.cloud，网页控制端连接主机；
  5) 协助码：另一 SSO 账号输入 → 确认框 → 控制 → 结束后码失效；
  6) 反编译检查：安装包内搜索不到任何 network_secret / 固定凭据；
  7) relhub 发布后，旧版本客户端自动更新到新版本并保持服务正常。
- 不提交、不推送，除非用户明确授权。
