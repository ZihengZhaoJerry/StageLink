// server/lib/spotify.ts
import { Router, Request, Response } from "express";
import { randomUUID, createHmac, timingSafeEqual } from "crypto";

const SPOTIFY_BASE_URL = "https://api.spotify.com/v1";

// Default production host for redirects (use your deployed Render URL)
const DEFAULT_APP_ORIGIN = "https://stormheck2025.onrender.com";
const DEFAULT_REDIRECT_PATH = "/api/spotify/callback";
const DEFAULT_REDIRECT_URI = process.env.SPOTIFY_REDIRECT_URI ?? (DEFAULT_APP_ORIGIN + DEFAULT_REDIRECT_PATH);
const DEFAULT_CLIENT_URL = process.env.CLIENT_URL ?? DEFAULT_APP_ORIGIN;

// Simple in-memory storage for a single performer's user tokens (demo only).
// For production you'd persist this per-user in a DB and secure it.
// Backwards-compatible single performer storage (kept for simple demo setups)
let performerTokens: {
  access_token: string;
  refresh_token: string;
  expires_at: number; // epoch seconds
  spotify_user_id?: string;
} | null = null;

// Multi-user token storage: map from your app user id -> tokens. Demo-only (in-memory).
const userTokens = new Map<string, { access_token: string; refresh_token: string; expires_at: number; spotify_user_id?: string }>();

// server-side OAuth state map to prevent trusting client-provided state payloads
// We prefer HMAC-signed state (stateless) when SPOTIFY_OAUTH_STATE_SECRET is set.
const oauthStates = new Map<string, { userId?: string | null; createdAt: number }>();

const STATE_SECRET = process.env.SPOTIFY_OAUTH_STATE_SECRET || process.env.SESSION_SECRET || null;
const STATE_MAX_AGE_MS = 1000 * 60 * 10; // 10 minutes

function base64urlEncode(buf: Buffer) {
  return buf.toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64urlDecode(str: string) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  // pad
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

function signState(payload: Record<string, any>) {
  if (!STATE_SECRET) return null;
  const json = JSON.stringify(payload);
  const body = Buffer.from(json);
  const sig = createHmac("sha256", STATE_SECRET).update(body).digest();
  return `${base64urlEncode(body)}.${base64urlEncode(sig)}`;
}

function verifyState(signed: string) {
  if (!STATE_SECRET) return null;
  const parts = signed.split(".");
  if (parts.length !== 2) return null;
  try {
    const body = base64urlDecode(parts[0]);
    const sig = base64urlDecode(parts[1]);
    const expected = createHmac("sha256", STATE_SECRET).update(body).digest();
    // timing safe compare
    if (sig.length !== expected.length) return null;
    if (!timingSafeEqual(sig, expected)) return null;
    const payload = JSON.parse(body.toString("utf8"));
    // check timestamp
    if (typeof payload.createdAt === "number") {
      if (Date.now() - payload.createdAt > STATE_MAX_AGE_MS) return null;
    }
    return payload;
  } catch (e) {
    return null;
  }
}

// router is declared below once before routes

// Search uses the server-side app token (client credentials)
// We'll keep the existing server-side spotifySearch function (client credentials)
let appTokenCache: { access_token: string; expires_at: number } | null = null;

async function getAppToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (appTokenCache && appTokenCache.expires_at - 30 > now) return appTokenCache.access_token;

  const id = process.env.SPOTIFY_CLIENT_ID;
  const secret = process.env.SPOTIFY_CLIENT_SECRET;
  if (!id || !secret) throw new Error("Missing SPOTIFY_CLIENT_ID or SPOTIFY_CLIENT_SECRET");

  const basic = Buffer.from(`${id}:${secret}`).toString("base64");
  const resp = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basic}` },
    body: new URLSearchParams({ grant_type: "client_credentials" }),
  });

  const data = await resp.json();
  if (!resp.ok) throw new Error(`Spotify token error: ${resp.status} ${JSON.stringify(data)}`);

  appTokenCache = { access_token: data.access_token, expires_at: Math.floor(Date.now() / 1000) + data.expires_in };
  return appTokenCache.access_token;
}

const router = Router();

export async function spotifySearch(q: string, type = "track") {
  const token = await getAppToken();
  const url = new URL(`${SPOTIFY_BASE_URL}/search`);
  url.searchParams.set("q", q);
  url.searchParams.set("type", type);

  const res = await fetch(url.toString(), { headers: { Authorization: `Bearer ${token}` } });
  const json = await res.json();
  if (!res.ok) throw new Error(`Spotify API error: ${res.status} ${JSON.stringify(json)}`);
  return json;
}

// ----------------- Routes -----------------

// Search route (existing behavior)
router.get("/search", async (req: Request, res: Response) => {
  try {
    const q = (req.query.q as string) ?? "";
    const type = (req.query.type as string) ?? "track";

    if (!q.trim()) return res.status(400).json({ error: "Missing search query (q parameter)" });

    const data = await spotifySearch(q, type);
    res.status(200).json(data);
  } catch (err: any) {
    console.error("Spotify route error:", err?.message ?? err);
    res.status(500).json({ error: err?.message ?? String(err) });
  }
});

// Start Spotify OAuth (redirects user to Spotify login/consent)
router.get("/login", (req: Request, res: Response) => {
  const clientId = process.env.SPOTIFY_CLIENT_ID;
  // prefer explicit env var, otherwise default to deployed app origin
  const redirectUri = (process.env.SPOTIFY_REDIRECT_URI ?? DEFAULT_REDIRECT_URI).toString();
  if (!clientId) return res.status(500).send("SPOTIFY_CLIENT_ID not configured");

  const scopes = ["user-modify-playback-state", "user-read-playback-state", "user-read-currently-playing"].join(" ");

  // allow caller to pass a userId so we can associate the Spotify account with that user
  const { userId } = req.query as { userId?: string };

  // Prefer HMAC-signed state (stateless) when possible, otherwise fall back to server-side map
  const payload = { userId: userId ?? null, createdAt: Date.now() };
  const signed = signState(payload);
  let state: string;
  if (signed) {
    state = signed;
  } else {
    const stateId = randomUUID();
    oauthStates.set(stateId, payload);
    state = stateId;
  }

  // Allow callers to opt into forcing the consent dialog via ?show_dialog=1. Default: no forced dialog.
  const showDialog = (req.query.show_dialog as string | undefined) === "1" ? "true" : undefined;
  const params = new URLSearchParams({ response_type: "code", client_id: clientId, scope: scopes, redirect_uri: redirectUri, state });
  if (showDialog) params.set("show_dialog", showDialog);
  const url = `https://accounts.spotify.com/authorize?${params.toString()}`;
  console.log(`[spotify] redirecting to authorize URL; redirect_uri=${redirectUri}`);
  console.log(`[spotify] full authorize url: ${url}`);
  res.redirect(url);
});

// Debug helper: return the computed redirect URI and an example authorize URL
router.get("/redirect-uri", (req: Request, res: Response) => {
  const clientId = process.env.SPOTIFY_CLIENT_ID;
  const redirectUri = (process.env.SPOTIFY_REDIRECT_URI ?? DEFAULT_REDIRECT_URI).toString();
  const scopes = ["user-modify-playback-state", "user-read-playback-state", "user-read-currently-playing"].join(" ");
  const params = new URLSearchParams({ response_type: "code", client_id: clientId ?? "<client_id>", scope: scopes, redirect_uri: redirectUri, show_dialog: "true" });
  const example = `https://accounts.spotify.com/authorize?${params.toString()}`;
  res.json({ redirectUri, exampleAuthorizeUrl: example, clientUrl: DEFAULT_CLIENT_URL });
});

// OAuth callback: exchange code for tokens and cache them for the performer
router.get("/callback", async (req: Request, res: Response) => {
  try {
    const code = req.query.code as string;
    const error = req.query.error as string | undefined;
    // Use the configured redirect URI (or the default for your deployed app)
    const redirectUri = (process.env.SPOTIFY_REDIRECT_URI ?? DEFAULT_REDIRECT_URI).toString();

    // parse stateId and retrieve optional userId from our server-side map
    const stateParam = req.query.state as string | undefined;
    let stateUserId: string | null = null;
    if (stateParam) {
      // legacy: check in-memory states first
      const stored = oauthStates.get(stateParam);
      if (stored) {
        stateUserId = stored.userId ?? null;
        // one-time use
        oauthStates.delete(stateParam);
      } else {
        // try verifying signed state
        const payload = verifyState(stateParam);
        if (payload) {
          stateUserId = payload.userId ?? null;
        } else {
          console.warn("Spotify callback received unknown or expired state id", stateParam);
        }
      }
    }

    if (error) {
      console.error("Spotify callback error:", error);
      return res.status(400).send(`Spotify auth failed: ${error}`);
    }
    if (!code) return res.status(400).send("Missing code");

    const id = process.env.SPOTIFY_CLIENT_ID!;
    const secret = process.env.SPOTIFY_CLIENT_SECRET!;
    const basic = Buffer.from(`${id}:${secret}`).toString("base64");

    const tokenResp = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: { Authorization: `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri }),
    });

    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok) {
      console.error("Spotify token exchange failed:", tokenJson);
      return res.status(500).json({ error: tokenJson });
    }

    // Build token object
    const tokenObj = {
      access_token: tokenJson.access_token,
      refresh_token: tokenJson.refresh_token,
      expires_at: Math.floor(Date.now() / 1000) + (tokenJson.expires_in || 3600),
    };

    // If a userId was supplied in the state, store tokens under that user
    if (stateUserId) {
      userTokens.set(stateUserId, tokenObj);
    } else {
      // fallback to the legacy single performerTokens
      performerTokens = tokenObj;
    }

    // Fetch user's Spotify id and display name for logs and status
    try {
      const meToken = tokenObj.access_token;
      const me = await fetch("https://api.spotify.com/v1/me", { headers: { Authorization: `Bearer ${meToken}` } });
      let meJson: any = null;
      try {
        meJson = await me.json();
      } catch (parseErr) {
        // If Spotify returned non-JSON (sometimes returns HTML), capture the text for debugging
        try {
          const txt = await me.text();
          console.warn("Spotify /me returned non-JSON during callback; raw body:", txt.slice(0, 1000));
        } catch (tErr) {
          console.warn("Spotify /me returned non-JSON and text read failed");
        }
      }
      if (me.ok && meJson) {
        const idToSet = meJson.id;
        if (stateUserId) {
          const existing = userTokens.get(stateUserId)!;
          existing.spotify_user_id = idToSet;
          userTokens.set(stateUserId, existing);
          console.log("Connected Spotify userId", stateUserId, "->", idToSet, meJson.display_name ?? "(no-name)");
        } else if (performerTokens) {
          performerTokens.spotify_user_id = idToSet;
          console.log("Connected Spotify performer:", idToSet, meJson.display_name ?? "(no-name)");
        }
      } else if (!me.ok) {
        // Log status and any JSON/text returned for debugging
        try {
          const bodyText = await me.text();
          console.warn(`Spotify /me call during callback failed: ${me.status} ${bodyText.slice(0, 1000)}`);
        } catch (e) {
          console.warn("Spotify /me call during callback failed and body could not be read");
        }
      }
    } catch (e) {
      console.warn("Failed to fetch Spotify /me after token exchange:", e);
    }

    // Redirect to client (dev default 5173) and indicate success
  const clientUrl = process.env.CLIENT_URL ?? DEFAULT_CLIENT_URL;
  const redirectTo = `${clientUrl}/?spotify_connected=1`;
    res.redirect(redirectTo);
  } catch (err: any) {
    console.error("Spotify callback exception:", err);
    res.status(500).json({ error: err?.message ?? String(err) });
  }
});

// Helper: refresh performer access token if expired
async function refreshPerformerTokenIfNeeded() {
  throw new Error("refreshPerformerTokenIfNeeded should not be called without a userId in the new multi-user flow");
}

// Refresh tokens for a given token object (in-place update)
async function refreshTokenIfNeededForTokenObj(tokenObj: { access_token: string; refresh_token: string; expires_at: number }) {
  const now = Math.floor(Date.now() / 1000);
  if (tokenObj.expires_at - 30 > now) return; // still valid

  const id = process.env.SPOTIFY_CLIENT_ID!;
  const secret = process.env.SPOTIFY_CLIENT_SECRET!;
  const basic = Buffer.from(`${id}:${secret}`).toString("base64");

  const resp = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { Authorization: `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokenObj.refresh_token }),
  });

  const json = await resp.json();
  if (!resp.ok) {
    // If the refresh token is invalid (e.g. revoked), surface an actionable error
    const errMsg = `Failed to refresh token: ${resp.status} ${JSON.stringify(json)}`;
    const invalidGrant = json?.error === "invalid_grant" || (json?.error_description ?? "").toLowerCase().includes("invalid grant");
    const err: any = new Error(errMsg);
    err.invalidGrant = invalidGrant;
    throw err;
  }

  tokenObj.access_token = json.access_token;
  tokenObj.expires_at = Math.floor(Date.now() / 1000) + (json.expires_in || 3600);
  if (json.refresh_token) tokenObj.refresh_token = json.refresh_token; // occasionally returned
}

// Helper: list available devices for a user token
async function listDevices(access_token: string) {
  try {
    const resp = await fetch(`${SPOTIFY_BASE_URL}/me/player/devices`, { headers: { Authorization: `Bearer ${access_token}` } });
    if (!resp.ok) {
      try {
        const txt = await resp.text();
        console.warn(`Spotify /me/player/devices returned ${resp.status}: ${txt.slice(0,1000)}`);
      } catch (e) {
        console.warn("Spotify /me/player/devices returned non-ok and body could not be read");
      }
      return null;
    }
    const json = await resp.json();
    return Array.isArray(json.devices) ? json.devices : json.devices ?? null;
  } catch (e) {
    return null;
  }
}

// Play a track on the connected performer's active Spotify device
router.post("/play", async (req: Request, res: Response) => {
  try {
    const { id, uri, userId } = req.body as { id?: string; uri?: string; userId?: string };

    // decide which token store to use: user-specific or legacy performerTokens
    let tokenObj: { access_token: string; refresh_token: string; expires_at: number } | null = null;
    if (userId) {
      const ut = userTokens.get(userId);
      if (!ut) return res.status(401).json({ error: `Spotify not connected for userId ${userId}` });
      tokenObj = ut;
    } else if (performerTokens) {
      tokenObj = performerTokens;
    } else {
      return res.status(401).json({ error: "No Spotify connection found. Connect via /api/spotify/login" });
    }

    try {
      await refreshTokenIfNeededForTokenObj(tokenObj);
    } catch (err: any) {
      console.error("Token refresh failed before play:", err?.message ?? err);
      // If refresh reported an invalid grant, clear stored tokens and ask client to reconnect
      if (err?.invalidGrant) {
        if (userId) userTokens.delete(userId);
        else performerTokens = null;
        return res.status(401).json({ error: "Spotify session expired or revoked. Please reconnect." });
      }
      return res.status(500).json({ error: err?.message ?? String(err) });
    }

    const playBody: any = {};
    if (uri) playBody.uris = [uri];
    else if (id) playBody.uris = [`spotify:track:${id}`];
    else return res.status(400).json({ error: "Missing id or uri in body" });

    // Always prefer the first available device (force device_id) to improve success rate
    const devicesInitially = await listDevices(tokenObj.access_token);
    let playUrl = `${SPOTIFY_BASE_URL}/me/player/play`;
    if (Array.isArray(devicesInitially) && devicesInitially.length > 0) {
      const chosen = devicesInitially[0];
      playUrl += `?device_id=${encodeURIComponent(chosen.id)}`;
    }

    const resp = await fetch(playUrl, {
      method: "PUT",
      headers: { Authorization: `Bearer ${tokenObj.access_token}`, "Content-Type": "application/json" },
      body: JSON.stringify(playBody),
    });

    if (resp.status === 204) return res.status(200).json({ ok: true });

    // Try to parse JSON response, but fall back to text when Spotify returns non-JSON
    let parsed: any = null;
    try {
      parsed = await resp.json();
    } catch (e) {
      try {
        parsed = await resp.text();
      } catch (e2) {
        parsed = null;
      }
    }

    // If 404 with no active device, provide helpful message
    if (resp.status === 404) {
  // Try to list devices and include them in the response for debugging
  const devices = await listDevices(tokenObj.access_token);
  return res.status(404).json({ error: "No active Spotify device found. Start Spotify on a device (phone/desktop) and try again.", spotify: parsed, devices });
    }

    if (!resp.ok) {
      console.error("Play failed:", resp.status, parsed ?? {});
      // If we got a 403 or other client error, try to discover devices and retry with a device_id
  const devices = await listDevices(tokenObj.access_token);
      if (Array.isArray(devices) && devices.length > 0) {
        const chosen = devices.find((d: any) => d.is_active) ?? devices[0];
        try {
          const retryUrl = `${SPOTIFY_BASE_URL}/me/player/play?device_id=${encodeURIComponent(chosen.id)}`;
          const retry = await fetch(retryUrl, {
            method: "PUT",
            headers: { Authorization: `Bearer ${tokenObj.access_token}`, "Content-Type": "application/json" },
            body: JSON.stringify(playBody),
          });
          if (retry.status === 204) return res.status(200).json({ ok: true, retried_with_device: chosen.id });
          let retryParsed: any = null;
          try {
            retryParsed = await retry.json();
          } catch (e) {
            retryParsed = await retry.text().catch(() => null);
          }
          // return the retry response if it provides more detail
          return res.status(retry.status).json({ error: retryParsed ?? `Play retry failed: ${retry.status}`, devices });
        } catch (e) {
          // fall through and return original error with devices
        }
      }
      // Forward the Spotify status and body to the client for easier debugging
      return res.status(resp.status).json({ error: parsed ?? `Play failed: ${resp.status}`, devices });
    }

    res.status(200).json({ ok: true, data: parsed });
  } catch (err: any) {
    console.error("/play error:", err?.message ?? err);
    res.status(500).json({ error: err?.message ?? String(err) });
  }
});

// Enqueue a track on the user's active Spotify device
router.post("/enqueue", async (req: Request, res: Response) => {
  try {
    const { id, uri, userId, device_id } = req.body as { id?: string; uri?: string; userId?: string; device_id?: string };

    let tokenObj: { access_token: string; refresh_token: string; expires_at: number } | null = null;
    if (userId) {
      const ut = userTokens.get(userId);
      if (!ut) return res.status(401).json({ error: `Spotify not connected for userId ${userId}` });
      tokenObj = ut;
    } else if (performerTokens) {
      tokenObj = performerTokens;
    } else {
      return res.status(401).json({ error: "No Spotify connection found. Connect via /api/spotify/login" });
    }

    try {
      await refreshTokenIfNeededForTokenObj(tokenObj);
    } catch (err: any) {
      console.error("Token refresh failed before enqueue:", err?.message ?? err);
      if (err?.invalidGrant) {
        if (userId) userTokens.delete(userId);
        else performerTokens = null;
        return res.status(401).json({ error: "Spotify session expired or revoked. Please reconnect." });
      }
      return res.status(500).json({ error: err?.message ?? String(err) });
    }

    const targetUri = uri ?? (id ? `spotify:track:${id}` : undefined);
    if (!targetUri) return res.status(400).json({ error: "Missing id or uri in body" });

    // Always prefer the first available device (force device_id) to improve success rate
    const devicesInitially = await listDevices(tokenObj.access_token);
    let q = `uri=${encodeURIComponent(targetUri)}`;
    if (Array.isArray(devicesInitially) && devicesInitially.length > 0) {
      const chosen = devicesInitially[0];
      q += `&device_id=${encodeURIComponent(chosen.id)}`;
    } else if (device_id) {
      q += `&device_id=${encodeURIComponent(device_id)}`;
    }

    const resp = await fetch(`${SPOTIFY_BASE_URL}/me/player/queue?${q}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tokenObj.access_token}` },
    });

    if (resp.status === 204) return res.status(200).json({ ok: true });

    // Try to parse JSON response, fallback to text
    let parsed: any = null;
    try {
      parsed = await resp.json();
    } catch (e) {
      try {
        parsed = await resp.text();
      } catch (e2) {
        parsed = null;
      }
    }

    if (resp.status === 404) {
      const devices = await listDevices(tokenObj.access_token);
      return res.status(404).json({ error: "No active Spotify device found. Start Spotify on a device (phone/desktop) and try again.", spotify: parsed, devices });
    }
    if (!resp.ok) {
      console.error("Enqueue failed:", resp.status, parsed ?? {});
      // Try to fetch devices and retry enqueue with device_id
      const devices = await listDevices(tokenObj.access_token);
      if (Array.isArray(devices) && devices.length > 0) {
        const chosen = devices.find((d: any) => d.is_active) ?? devices[0];
        try {
          const retryQ = `uri=${encodeURIComponent(targetUri)}&device_id=${encodeURIComponent(chosen.id)}`;
          const retry = await fetch(`${SPOTIFY_BASE_URL}/me/player/queue?${retryQ}`, {
            method: "POST",
            headers: { Authorization: `Bearer ${tokenObj.access_token}` },
          });
          if (retry.status === 204) return res.status(200).json({ ok: true, retried_with_device: chosen.id });
          let retryParsed: any = null;
          try {
            retryParsed = await retry.json();
          } catch (e) {
            retryParsed = await retry.text().catch(() => null);
          }
          return res.status(retry.status).json({ error: retryParsed ?? `Enqueue retry failed: ${retry.status}`, devices });
        } catch (e) {
          // fall through and return original error
        }
      }
      return res.status(resp.status).json({ error: parsed ?? `Enqueue failed: ${resp.status}`, devices });
    }

    res.status(200).json({ ok: true, data: parsed });
  } catch (err: any) {
    console.error("/enqueue error:", err?.message ?? err);
    res.status(500).json({ error: err?.message ?? String(err) });
  }
});

// Return connection status for the performer (demo)
router.get("/status", async (req: Request, res: Response) => {
  const { userId } = req.query as { userId?: string };
  let tokenObj = null;
  if (userId) tokenObj = userTokens.get(userId) ?? null;
  else tokenObj = performerTokens;

  if (!tokenObj) return res.status(200).json({ connected: false });

  // attempt to fetch display name if we didn't store it
  let display_name: string | undefined = undefined;
  try {
    // try refreshing first so we return accurate status
    try {
      await refreshTokenIfNeededForTokenObj(tokenObj as any);
    } catch (err: any) {
      console.error("Token refresh failed during /status:", err?.message ?? err);
      if (err?.invalidGrant) {
        // clear stored tokens and report disconnected
        if (userId) userTokens.delete(userId);
        else performerTokens = null;
        return res.status(200).json({ connected: false });
      }
      // continue to try /me even if refresh failed for other reasons
    }

    const me = await fetch(`${SPOTIFY_BASE_URL}/me`, { headers: { Authorization: `Bearer ${tokenObj.access_token}` } });
    if (me.ok) {
      try {
        const j = await me.json();
        display_name = j.display_name;
      } catch (parseErr) {
        try {
          const txt = await me.text();
          console.warn(`Spotify /me during /status returned non-JSON: ${txt.slice(0,1000)}`);
        } catch (e) {
          console.warn("Spotify /me during /status returned non-JSON and body could not be read");
        }
      }
    } else {
      try {
        const txt = await me.text();
        console.warn(`Spotify /me during /status failed: ${me.status} ${txt.slice(0,1000)}`);
      } catch (e) {
        console.warn("Spotify /me during /status failed and body could not be read");
      }
    }
  } catch (e) {
    // ignore
  }
  return res.status(200).json({ connected: true, spotify_user_id: tokenObj.spotify_user_id, display_name });
});

// Debug endpoint: return lightweight token metadata for one or all users (no secrets)
router.get("/debug", (req: Request, res: Response) => {
  const { userId } = req.query as { userId?: string };

  if (userId) {
    const t = userTokens.get(userId) ?? null;
    if (!t) return res.status(200).json({ connected: false });
    return res.status(200).json({ connected: true, spotify_user_id: t.spotify_user_id ?? null, expires_at: t.expires_at ?? null });
  }

  // list all known user token metadata (do not expose tokens)
  const list = Array.from(userTokens.entries()).map(([uid, tok]) => ({ userId: uid, spotify_user_id: tok.spotify_user_id ?? null, expires_at: tok.expires_at ?? null }));
  return res.status(200).json({ users: list, performerConnected: Boolean(performerTokens) });
});

// Disconnect performer or user tokens: clear tokens
router.post("/disconnect", (req: Request, res: Response) => {
  const { userId } = req.query as { userId?: string };
  if (userId) {
    userTokens.delete(userId);
    return res.status(200).json({ ok: true });
  }
  performerTokens = null;
  return res.status(200).json({ ok: true });
});

export default router;
