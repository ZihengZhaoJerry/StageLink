import { useState, useEffect, useRef, useMemo } from "react";
import { getAuth, onAuthStateChanged } from "firebase/auth";
import { app as firebaseApp } from "@/lib/firebaseConfig";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import QueueItem from "@/components/QueueItem";
import NowPlaying from "@/components/NowPlaying";
import { useLocation } from "wouter";
import EmptyState from "@/components/EmptyState";
import { ListMusic, Search as SearchIcon } from "lucide-react";
import ThemeToggle from "@/components/ThemeToggle";
import { Button } from "@/components/ui/button";
import SearchBar from "@/components/SearchBar";
import { useToast } from "@/hooks/use-toast";
import { searchSpotify } from "../lib/spotifyHelper";

// Helper to pick a good album image
function pickImage(
  images: Array<{ url: string; width?: number; height?: number }> = []
) {
  if (!images.length) return undefined;
  const byClosest300 = [...images].sort(
    (a, b) =>
      Math.abs((a.width ?? 0) - 300) - Math.abs((b.width ?? 0) - 300)
  );
  return byClosest300[0]?.url ?? images[0]?.url;
}

// Map Spotify API response to QueueItem-friendly shape
function mapSpotifyTracksToQueue(data: any): UISong[] {
  if (!data?.tracks?.items) return [];
  return data.tracks.items.map((t: any) => ({
    id: t.id,
    title: t.name,
    artist: (t.artists ?? []).map((a: any) => a.name).join(", "),
    album: t.album?.name ?? "",
    albumArt: pickImage(t.album?.images ?? []),
    requestedBy: "", // You can fill this if you have user info
    previewUrl: t.preview_url, // <-- add this line
    uri: t.uri, // spotify:track:<id>
  }));
}

type UISong = {
  id: string;
  title: string;
  artist: string;
  album: string;
  albumArt?: string;
  requestedBy?: string;
  previewUrl?: string; // <-- add this line
  uri?: string;
};

const mockNowPlaying = {
  title: "Bohemian Rhapsody",
  artist: "Queen",
  album: "A Night at the Opera",
};

export default function LandingPage() {
  const [activeTab, setActiveTab] = useState("search");
  const [, setLocation] = useLocation();

  const [searchQuery, setSearchQuery] = useState("");
  const [results, setResults] = useState<UISong[]>([]);
  const [queue, setQueue] = useState<UISong[]>([]);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();
  const debounceMs = 350;
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [nowPlaying, setNowPlaying] = useState<UISong | null>(null);
  const [spotifyStatus, setSpotifyStatus] = useState<{ connected: boolean; display_name?: string } | null>(null);
  const [appUserId, setAppUserId] = useState<string | null>(null);

  const eventId = "stormheck2025"; // Use the same eventId as in QRCodePage

  useEffect(() => {
    // Fetch the queue for this event
    fetch(`/api/song-queue?eventId=${eventId}`)
      .then(res => res.json())
      .then(data => {
        // Ensure data is always an array
        setQueue(Array.isArray(data) ? data : []);
      })
      .catch(() => setQueue([])); // fallback on error
  }, []);

  useEffect(() => {
    if (timerRef.current) clearTimeout(timerRef.current);

    if (!searchQuery.trim()) {
      setResults([]);
      setLoading(false);
      return;
    }

    setLoading(true);
    timerRef.current = setTimeout(async () => {
      try {
        const data = await searchSpotify(searchQuery, "track");
        const mapped = mapSpotifyTracksToQueue(data);
        setResults(mapped);
      } catch (err: any) {
        toast({
          title: "Search failed",
          description: err?.message ?? "Could not fetch songs.",
          variant: "destructive",
        });
      } finally {
        setLoading(false);
      }
    }, debounceMs);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [searchQuery, toast]);

  // subscribe to Firebase auth to get signed-in app user id
  useEffect(() => {
    const unsub = onAuthStateChanged(getAuth(firebaseApp), (user) => {
      setAppUserId(user?.uid ?? null);
    });
    return () => unsub();
  }, []);

  // fetch spotify connection status for header (re-run when appUserId changes)
  useEffect(() => {
    (async () => {
      try {
        const q = appUserId ? `?userId=${encodeURIComponent(appUserId)}` : "";
        const resp = await fetch(`/api/spotify/status${q}`);
        if (!resp.ok) return setSpotifyStatus({ connected: false });
        const json = await resp.json();
        setSpotifyStatus({ connected: Boolean(json?.connected), display_name: json?.display_name });
      } catch {
        setSpotifyStatus({ connected: false });
      }
    })();
  }, [appUserId]);

  const emptyState = useMemo(() => {
    if (!searchQuery.trim()) {
      return (
        <EmptyState
          icon={ListMusic}
          title="Search for a song"
          description="Start typing to find songs to add to the queue"
        />
      );
    }
    if (loading) {
      return (
        <EmptyState
          icon={SearchIcon}
          title="Searching…"
          description="Looking for tracks that match your query"
        />
      );
    }
    if (results.length === 0) {
      return (
        <EmptyState
          icon={SearchIcon}
          title="No songs found"
          description="Try searching for a different song, artist, or album"
        />
      );
    }
    return null;
  }, [loading, results.length, searchQuery]);

  // Add song to queue if not already present
  const handleAddToQueue = (song: UISong) => {
    if (queue.some((s) => s.id === song.id)) {
      toast({
        title: "Already in queue",
        description: `"${song.title}" is already in the queue.`,
      });
      return;
    }
    // Always check server-side Spotify connection for the signed-in user before enqueueing
    (async () => {
      let added = false;
      try {
        const q = appUserId ? `?userId=${encodeURIComponent(appUserId)}` : "";
        const statusResp = await fetch(`/api/spotify/status${q}`);
        const statusJson = statusResp.ok ? await statusResp.json().catch(() => ({})) : { connected: false };
        const connected = Boolean(statusJson?.connected);
        setSpotifyStatus({ connected, display_name: statusJson?.display_name });

        if (connected && song.uri) {
          try {
            const body: any = { uri: song.uri };
            if (appUserId) body.userId = appUserId;
            const resp = await fetch(`/api/spotify/enqueue`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body),
            });
            if (resp.ok) {
              setQueue((prev) => [...prev, song]);
              toast({ title: "Added to Spotify queue", description: `"${song.title}" was added to Spotify.` });
              added = true;
              return;
            }
                const j = await resp.json().catch(() => ({}));
                // fallback to local queue
                const errDesc = typeof j?.error === "string" ? j.error : JSON.stringify(j?.error ?? j ?? `Could not add to Spotify: ${resp.status}`);
                toast({ title: "Added to queue (local)", description: errDesc });
          } catch (e: any) {
                const desc = typeof e?.message === "string" ? e.message : JSON.stringify(e ?? String(e));
                toast({ title: "Added to queue (local)", description: desc });
          }
        }
      } catch (err) {
        // ignore and fallback to local queue
      }
      if (!added) {
        setQueue((prev) => [...prev, song]);
        toast({ title: "Added to queue", description: `"${song.title}" has been added to the queue.` });
      }
    })();
    return;
  };

  // Set now playing from queue
  const handlePlayFromQueue = (song: UISong) => {
    // Immediately update UI so it doesn't go blank
    setNowPlaying(song);
    setActiveTab("now-playing");

    // If Spotify is connected, ask server to start playback (include appUserId when available)
    if (spotifyStatus?.connected && song.uri) {
      (async () => {
        try {
          const body: any = { uri: song.uri };
          if (appUserId) body.userId = appUserId;
          const resp = await fetch(`/api/spotify/play`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          });
          if (resp.ok) {
            toast({ title: "Playing on Spotify", description: `"${song.title}" should start playing on the connected Spotify device.` });
          } else {
                  const j = await resp.json().catch(() => ({}));
                  const desc = typeof j?.error === "string" ? j.error : JSON.stringify(j?.error ?? j ?? `Could not play on Spotify: ${resp.status}`);
                  toast({ title: "Play failed", description: desc, variant: "destructive" });
          }
        } catch (e: any) {
                const desc = typeof e?.message === "string" ? e.message : JSON.stringify(e ?? String(e));
                toast({ title: "Play failed", description: desc, variant: "destructive" });
        }
      })();
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b p-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
            <div onClick={() => setLocation("/")} style={{cursor: 'pointer'}}>
              <h1 className="text-3xl font-bold">SongRequest</h1>
              <p className="text-muted-foreground">Manage song requests in real-time</p>
            </div>
            <div className="flex items-center gap-2">
              <div className="text-right mr-4">
                <p className="text-2xl font-bold text-primary" data-testid="text-queue-count">
                  {queue.length}
                </p>
                <p className="text-sm text-muted-foreground">in queue</p>
              </div>

              {/* Spotify connect / disconnect UI */}
              <div className="flex items-center gap-2 mr-2">
                {spotifyStatus?.connected ? (
                  <>
                    <div className="text-sm text-muted-foreground">Connected: {spotifyStatus.display_name ?? "Spotify"}</div>
                    <Button
                      variant="outline"
                      size={"sm" as any}
                      onClick={async () => {
                        try {
                          const q = appUserId ? `?userId=${encodeURIComponent(appUserId)}` : "";
                          const resp = await fetch(`/api/spotify/disconnect${q}`, { method: "POST" });
                          if (resp.ok) {
                            setSpotifyStatus({ connected: false });
                            toast({ title: "Spotify disconnected" });
                          } else {
                            const j = await resp.json().catch(() => ({}));
                            toast({ title: "Disconnect failed", description: j?.error ?? "Unknown error", variant: "destructive" });
                          }
                        } catch (e: any) {
                          toast({ title: "Disconnect failed", description: e?.message ?? String(e), variant: "destructive" });
                        }
                      }}
                    >
                      Disconnect
                    </Button>
                  </>
                ) : (
                  <Button
                    variant="outline"
                    onClick={() => {
                      // redirect to server login which will forward to Spotify
                      const url = appUserId ? `/api/spotify/login?userId=${encodeURIComponent(appUserId)}` : `/api/spotify/login`;
                      window.location.href = url;
                    }}
                  >
                    Connect Spotify
                  </Button>
                )}
              </div>

            <ThemeToggle />
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto p-6 relative">
        <div className="absolute right-0 top-0 mt-2 mr-2 z-10">
          <Button
            variant="outline"
            className="text-lg h-14 px-8"
            onClick={() => setLocation("/qr-code")}
            data-testid="button-qr-code"
          >
            Show QR Code
          </Button>
        </div>
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full max-w-xl grid-cols-3 mx-auto mb-6">
            <TabsTrigger value="search" data-testid="tab-search">
              Search
            </TabsTrigger>
            <TabsTrigger value="queue" data-testid="tab-queue">
              Queue
            </TabsTrigger>
            <TabsTrigger value="now-playing" data-testid="tab-now-playing">
              Now Playing
            </TabsTrigger>
          </TabsList>
          {/* Search Tab */}
          <TabsContent value="search" className="space-y-4">
            <div className="mb-6">
              <SearchBar value={searchQuery} onChange={setSearchQuery} />
            </div>
            {emptyState ? (
              emptyState
            ) : (
              results.map((song, index) => (
                <div
                  key={song.id}
                  onClick={() => handleAddToQueue(song)}
                  style={{ cursor: "pointer" }}
                  className={
                    queue.some((s) => s.id === song.id)
                      ? "opacity-60 pointer-events-none"
                      : "hover:bg-accent/40 rounded transition"
                  }
                  data-testid={`search-result-${song.id}`}
                >
                  <QueueItem
                    position={index + 1}
                    title={song.title}
                    artist={song.artist}
                    requestedBy={song.requestedBy}
                    isPlaying={false}
                  />
                </div>
              ))
            )}
          </TabsContent>
          {/* Queue Tab */}
          <TabsContent value="queue" className="space-y-4">
            {queue.length === 0 ? (
              <EmptyState
                icon={ListMusic}
                title="Queue is empty"
                description="Add songs from the search tab"
              />
            ) : (
              queue.map((song, index) => (
                <div
                  key={song.id}
                  onClick={() => handlePlayFromQueue(song)}
                  style={{ cursor: "pointer" }}
                  className={
                    nowPlaying?.id === song.id
                      ? "ring-2 ring-primary rounded"
                      : "hover:bg-accent/40 rounded transition"
                  }
                  data-testid={`queue-item-${song.id}`}
                >
                  <QueueItem
                    position={index + 1}
                    title={song.title}
                    artist={song.artist}
                    requestedBy={song.requestedBy}
                    isPlaying={nowPlaying?.id === song.id}
                  />
                </div>
              ))
            )}
          </TabsContent>
          {/* Now Playing Tab */}
          <TabsContent value="now-playing">
            <div className="max-w-3xl mx-auto">
              {nowPlaying ? (
                <NowPlaying
                  title={nowPlaying.title}
                  artist={nowPlaying.artist}
                  album={nowPlaying.album}
                  albumArt={nowPlaying.albumArt}
                  previewUrl={nowPlaying.previewUrl} // <-- pass previewUrl
                  spotifyUri={nowPlaying.uri}
                />
              ) : (
                <EmptyState
                  icon={ListMusic}
                  title="No song playing"
                  description="Select a song from the queue to play"
                />
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
