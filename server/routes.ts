// server/routes.ts
import express, { Express, Request, Response, NextFunction } from "express";
import { createServer, Server } from "http";

// Mount sub-routers
import spotifyRouter from "./lib/spotify";

// In-memory event queues (replace with DB in production)
const eventQueues: Record<string, any[]> = {};

export async function registerRoutes(app: Express): Promise<Server> {
  // Basic middleware (adjust as needed)
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Health check
  app.get("/api/health", (_req: Request, res: Response) => {
    res.json({ ok: true });
  });

  // ---- Your API routes ----
  app.use("/api/spotify", spotifyRouter);

  // Song queue endpoints
  app.get("/api/song-queue", (req: Request, res: Response) => {
    const eventId = req.query.eventId as string;
    if (!eventId) return res.status(400).json({ error: "Missing eventId" });
    res.json(eventQueues[eventId] || []);
  });

  app.post("/api/song-queue", (req: Request, res: Response) => {
    const { eventId, session, songs } = req.body;
    if (!eventId || !Array.isArray(songs)) {
      return res.status(400).json({ error: "Missing eventId or songs" });
    }
    // Optionally deduplicate by song id
    eventQueues[eventId] = eventQueues[eventId] || [];
    const existingIds = new Set(eventQueues[eventId].map((s: any) => s.id));
    const newSongs = songs.filter((s: any) => !existingIds.has(s.id));
    eventQueues[eventId].push(...newSongs);
    res.json({ success: true });
  });

  // Remove one or more songs from an event queue
  app.post("/api/song-queue/remove", (req: Request, res: Response) => {
    const { eventId, songId, songIds } = req.body;
    if (!eventId || (!songId && !Array.isArray(songIds))) {
      return res.status(400).json({ error: "Missing eventId or songId/songIds" });
    }
    const idsToRemove = new Set<string>();
    if (songId) idsToRemove.add(songId);
    if (Array.isArray(songIds)) songIds.forEach((id: string) => idsToRemove.add(id));

    eventQueues[eventId] = (eventQueues[eventId] || []).filter((s: any) => !idsToRemove.has(s.id));
    return res.json({ success: true });
  });

  // 404 for unknown API routes
  app.use("/api/*", (_req: Request, res: Response) => {
    res.status(404).json({ error: "Not found" });
  });

  // Centralized error handler
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    console.error(err);
    const status = typeof err.status === "number" ? err.status : 500;
    res.status(status).json({
      error: err?.message ?? "Internal Server Error",
    });
  });

  // Create and return the HTTP server
  const httpServer = createServer(app);
  return httpServer;
}

export default registerRoutes;
