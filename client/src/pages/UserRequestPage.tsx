"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "wouter";
import SearchBar from "@/components/SearchBar";
import SongCard from "@/components/SongCard";
import ThemeToggle from "@/components/ThemeToggle";
import EmptyState from "@/components/EmptyState";
import { Music, Search as SearchIcon, ListMusic } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { searchSpotify } from "../lib/spotifyHelper";

// Choose a good-sized album image from Spotify's images array
function pickImage(
  images: Array<{ url: string; width?: number; height?: number }> = []
) {
  if (!images.length) return undefined;
  // Prefer ~300px wide if available
  const byClosest300 = [...images].sort(
    (a, b) =>
      Math.abs((a.width ?? 0) - 300) - Math.abs((b.width ?? 0) - 300)
  );
  return byClosest300[0]?.url ?? images[0]?.url;
}

// Convert Spotify API response into your SongCard-friendly shape
function mapSpotifyTracksToCards(data: any): UISong[] {
  if (!data?.tracks?.items) return [];
  return data.tracks.items.map((t: any) => ({
    id: t.id,
    title: t.name,
    artist: (t.artists ?? []).map((a: any) => a.name).join(", "),
    album: t.album?.name ?? "",
    albumArt: pickImage(t.album?.images ?? []),
    uri: t.uri,
  }));
}

// ---------- Types ----------

type UISong = {
  id: string;
  title: string;
  artist: string;
  album: string;
  albumArt?: string; // <— add this so SongCard can show the cover
  uri?: string;
};

// Example function to add a song to the queue
async function addSongToQueue(song: UISong, eventId: string) {
  await fetch(`/api/song-queue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...song, eventId }),
  });
}

// ---------- Page ----------

export default function UserRequestPage() {
  const saved = sessionStorage.getItem("qrSession");
  const [searchQuery, setSearchQuery] = useState("");
  const [results, setResults] = useState<UISong[]>([]);
  const [requestedSongs, setRequestedSongs] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();
  const [submitting, setSubmitting] = useState(false);
  const [location] = useLocation();
  // Prefer reading query params from the real browser URL (location from wouter may omit query on some navigations)
  const params = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : new URLSearchParams(location.split("?")[1]);
  const eventId = params.get("eventId");
  const session = params.get("session");

  // If eventId is missing, show a helpful message and disable submit to avoid 400 from the server
  useEffect(() => {
    if (!eventId) {
      toast({ title: "Invalid request link", description: "This request link is missing an event id. Please scan the QR code again or ask the host for a correct link.", variant: "destructive" });
    }
  }, [eventId, toast]);

  // simple debounce to avoid spamming your API
  const debounceMs = 350;
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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
        const mapped = mapSpotifyTracksToCards(data);
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

    // cleanup
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [searchQuery, toast]);

  const emptyState = useMemo(() => {
    if (!searchQuery.trim()) {
      return (
        <EmptyState
          icon={Music}
          title="Search for a song"
          description="Start typing to find songs you'd like to request"
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

  const handleSongRequest = (songId: string, songTitle: string) => {
    if (requestedSongs.includes(songId)) {
      setRequestedSongs((prev) => prev.filter((id) => id !== songId));
      toast({
        title: "Request removed",
        description: `"${songTitle}" has been removed from your requests`,
      });
    } else {
      setRequestedSongs((prev) => [...prev, songId]);
      toast({
        title: "Song requested!",
        description: `"${songTitle}" has been added to the queue`,
      });
    }
  };

  // Helper to get full song info for requested songs
  const requestedSongObjs = useMemo(
    () => results.filter((s) => requestedSongs.includes(s.id)),
    [results, requestedSongs]
  );

  // Submit handler
  const submitRequests = async () => {
    if (requestedSongs.length === 0) return;
    if (!eventId) {
      toast({ title: "Missing event", description: "Cannot submit requests: missing event id.", variant: "destructive" });
      return;
    }
    setSubmitting(true);
    try {
      // Send only the song IDs, or send full song info as needed by your backend
      const res = await fetch("/api/song-queue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ eventId, session, songs: requestedSongObjs }),
      });
      if (!res.ok) throw new Error("Failed to submit requests");
      setRequestedSongs([]);
      toast({
        title: "Requests submitted!",
        description: "Your song requests have been added to the queue.",
        variant: "default",
      });
    } catch (err: any) {
      toast({
        title: "Submission failed",
        description: err?.message ?? "Could not submit your requests.",
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <div className="flex items-center justify-between p-4 border-b">
        <h1 className="text-2xl font-bold">Request a Song</h1>
            <ThemeToggle />
      </div>
      <div className="flex flex-1 min-h-0">
        {/* Left: Search & Results */}
        <div className="flex-1 border-r max-w-2xl flex flex-col">
          <div className="p-4">
            <SearchBar value={searchQuery} onChange={setSearchQuery} />
          </div>
          <div className="flex-1 overflow-y-auto p-4 pb-24">
            {emptyState ? (
              emptyState
            ) : (
              <div className="space-y-3">
                {results.map((song) => (
                  <SongCard
                    key={song.id}
                    id={song.id}
                    title={song.title}
                    artist={song.artist}
                    album={song.album}
                    albumArt={song.albumArt}   // <-- shows the album cover
                    isRequested={requestedSongs.includes(song.id)}
                    onClick={() => handleSongRequest(song.id, song.title)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
        {/* Right: Queue Panel */}
        <div className="w-full max-w-md flex flex-col bg-muted/40">
          <div className="p-4 border-b flex items-center gap-2">
            <ListMusic className="w-5 h-5" />
            <span className="font-semibold text-lg">Your Queue</span>
            <span className="ml-auto text-sm text-muted-foreground">
              {requestedSongs.length} selected
            </span>
          </div>
          <div className="flex-1 overflow-y-auto p-4">
            {requestedSongs.length === 0 ? (
              <EmptyState
                icon={ListMusic}
                title="No songs in queue"
                description="Your selected songs will appear here"
              />
            ) : (
              <div className="space-y-3">
                {requestedSongObjs.map((song) => (
                  <SongCard
                    key={song.id}
                    id={song.id}
                    title={song.title}
                    artist={song.artist}
                    album={song.album}
                    albumArt={song.albumArt}
                    isRequested={true}
                    onClick={() => handleSongRequest(song.id, song.title)}
                  />
                ))}
              </div>
            )}
          </div>
          <div className="p-4 border-t">
            <Button
              className="w-full h-12 text-lg"
              data-testid="button-submit-requests"
              disabled={requestedSongs.length === 0 || submitting}
              onClick={submitRequests}
            >
              {submitting ? "Submitting..." : `Submit Requests (${requestedSongs.length})`}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}