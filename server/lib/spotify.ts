// server/lib/spotify.ts
import { Router, Request, Response } from "express";
import { randomUUID } from "crypto";

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
const oauthStates = new Map<string, { userId?: string | null; createdAt: number }>();

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

  // Generate a short opaque state id and store server-side to avoid trusting arbitrary client values
  const stateId = randomUUID();
  oauthStates.set(stateId, { userId: userId ?? null, createdAt: Date.now() });
  const state = stateId;

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
      const stored = oauthStates.get(stateParam);
      if (stored) {
        stateUserId = stored.userId ?? null;
        // one-time use
        oauthStates.delete(stateParam);
      } else {
        console.warn("Spotify callback received unknown or expired state id", stateParam);
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
      const meJson = await me.json();
      if (me.ok) {
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

    const resp = await fetch(`${SPOTIFY_BASE_URL}/me/player/play`, {
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
      return res.status(404).json({ error: "No active Spotify device found. Start Spotify on a device (phone/desktop) and try again.", spotify: parsed });
    }

    if (!resp.ok) {
      console.error("Play failed:", resp.status, parsed ?? {});
      // Forward the Spotify status and body to the client for easier debugging
      return res.status(resp.status).json({ error: parsed ?? `Play failed: ${resp.status}` });
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

    const q = `uri=${encodeURIComponent(targetUri)}` + (device_id ? `&device_id=${encodeURIComponent(device_id)}` : "");
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
      return res.status(404).json({ error: "No active Spotify device found. Start Spotify on a device (phone/desktop) and try again.", spotify: parsed });
    }
    if (!resp.ok) {
      console.error("Enqueue failed:", resp.status, parsed ?? {});
      return res.status(resp.status).json({ error: parsed ?? `Enqueue failed: ${resp.status}` });
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
      const j = await me.json();
      display_name = j.display_name;
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
