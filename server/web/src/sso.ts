/**
 * Browser OAuth 2.0 Authorization Code + PKCE (S256) + RFC 9449 DPoP (ES256) sign-in
 * against sso.moonl.cloud using the registered web SPA client `ms_bZjB-HZgyTyylUAWQ8il`.
 */

export const SSO_ISSUER = "https://sso.moonl.cloud";
export const WEB_CLIENT_ID = "ms_bZjB-HZgyTyylUAWQ8il";
export const SSO_SCOPE = "openid profile offline_access";
export const SSO_RESOURCE = "https://remote.moonl.cloud";

const STORAGE_KEY = "moonrd_web_session";
const PKCE_KEY = "moonrd_pkce_pending";

export interface WebSession {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  userSub: string;
  displayName: string;
}

function base64Url(bytes: Uint8Array): string {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlJson(obj: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function sha256Base64Url(input: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return base64Url(new Uint8Array(hash));
}

async function computeJkt(pubJwk: JsonWebKey): Promise<string> {
  // RFC 7638 canonical JWK JSON for EC P-256
  const canonical = JSON.stringify({ crv: pubJwk.crv, kty: pubJwk.kty, x: pubJwk.x, y: pubJwk.y });
  return sha256Base64Url(canonical);
}

async function createDpopProof(
  privKey: CryptoKey,
  pubJwk: JsonWebKey,
  htm: string,
  htu: string,
  nonce?: string
): Promise<string> {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y },
  };
  const payload: Record<string, unknown> = {
    jti: base64Url(crypto.getRandomValues(new Uint8Array(16))),
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
  };
  if (nonce) payload.nonce = nonce;
  const input = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privKey,
    new TextEncoder().encode(input)
  );
  return `${input}.${base64Url(new Uint8Array(sig))}`;
}

export function loadSession(): WebSession | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as WebSession;
    if (Date.now() > parsed.expiresAt) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function signOut(): void {
  sessionStorage.removeItem(STORAGE_KEY);
}

export async function startSignIn(): Promise<void> {
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = await sha256Base64Url(verifier);
  const state = base64Url(crypto.getRandomValues(new Uint8Array(16)));
  const redirectUri = `${window.location.origin}/auth/callback`;

  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const dpopJkt = await computeJkt(pubJwk);

  sessionStorage.setItem(
    PKCE_KEY,
    JSON.stringify({ verifier, state, redirectUri, pubJwk, privJwk })
  );

  const params = new URLSearchParams({
    response_type: "code",
    client_id: WEB_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: SSO_SCOPE,
    resource: SSO_RESOURCE,
    code_challenge: challenge,
    code_challenge_method: "S256",
    dpop_jkt: dpopJkt,
    state,
  });
  window.location.assign(`${SSO_ISSUER}/oauth/authorize?${params.toString()}`);
}

export async function completeSignInIfCallback(): Promise<WebSession | null> {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const state = params.get("state");
  const err = params.get("error");
  if (err) {
    const desc = params.get("error_description") ?? "";
    window.history.replaceState({}, "", "/");
    throw new Error(`${err}${desc ? `: ${desc}` : ""}`);
  }
  if (!code || !state) return loadSession();

  const raw = sessionStorage.getItem(PKCE_KEY);
  sessionStorage.removeItem(PKCE_KEY);
  window.history.replaceState({}, "", "/");

  if (!raw) throw new Error("Missing PKCE state");
  const pending = JSON.parse(raw) as {
    verifier: string;
    state: string;
    redirectUri: string;
    pubJwk: JsonWebKey;
    privJwk: JsonWebKey;
  };
  if (pending.state !== state) throw new Error("OAuth state mismatch");

  const privKey = await crypto.subtle.importKey(
    "jwk",
    pending.privJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const tokenUrl = `${SSO_ISSUER}/oauth/token`;
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: WEB_CLIENT_ID,
    code,
    redirect_uri: pending.redirectUri,
    code_verifier: pending.verifier,
    resource: SSO_RESOURCE,
  });

  let nonce: string | undefined;
  let tokenResp: Response | null = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const proof = await createDpopProof(privKey, pending.pubJwk, "POST", tokenUrl, nonce);
    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        DPoP: proof,
      },
      body,
    });
    const serverNonce = resp.headers.get("DPoP-Nonce");
    if (resp.status === 400 && serverNonce && attempt === 0) {
      nonce = serverNonce;
      continue;
    }
    tokenResp = resp;
    break;
  }

  if (!tokenResp || !tokenResp.ok) {
    throw new Error(`Token exchange failed (${tokenResp?.status ?? 0})`);
  }
  const tok = (await tokenResp.json()) as {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
  };

  const uiResp = await fetch(`${SSO_ISSUER}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${tok.access_token}` },
  });
  const info = uiResp.ok
    ? ((await uiResp.json()) as { sub: string; name?: string; preferred_username?: string })
    : { sub: "unknown" };

  const session: WebSession = {
    accessToken: tok.access_token,
    refreshToken: tok.refresh_token,
    expiresAt: Date.now() + Math.max(60, tok.expires_in - 30) * 1000,
    userSub: info.sub,
    displayName: info.name ?? info.preferred_username ?? info.sub,
  };
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  return session;
}
