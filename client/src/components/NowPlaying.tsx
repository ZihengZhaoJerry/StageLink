import { Music, Pause } from "lucide-react";
import { Card } from "@/components/ui/card";
import { useEffect, useRef, useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { getAuth, onAuthStateChanged } from "firebase/auth";
import { app as firebaseApp } from "@/lib/firebaseConfig";

interface NowPlayingProps {
  title: string;
  artist: string;
  albumArt?: string;
  album?: string;
  previewUrl?: string;
  spotifyUri?: string; // spotify:track:<id>
}

export default function NowPlaying({ title, artist, albumArt, album, previewUrl, spotifyUri }: NowPlayingProps) {
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [isPlaying, setIsPlaying] = useState(true);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(30); // Spotify preview is 30s

  useEffect(() => {
    setCurrentTime(0);
    setIsPlaying(true);
    if (audioRef.current) {
      audioRef.current.currentTime = 0;
      audioRef.current.play();
    }
    // Try to trigger playback on connected Spotify account (server-side) if we have a spotifyUri prop.
    (async () => {
      try {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        const spotifyUri = (arguments[0] && arguments[0].spotifyUri) || undefined;
      } catch {}
      // No-op here; actual play is triggered separately via explicit play button or by parent.
    })();
  }, [previewUrl]);

  // Check connected status for performer Spotify account
  const [spotifyConnected, setSpotifyConnected] = useState<boolean | null>(null);
  const [appUserId, setAppUserId] = useState<string | null>(null);
  useEffect(() => {
    (async () => {
      try {
        const resp = await fetch(`/api/spotify/status`);
        if (!resp.ok) return setSpotifyConnected(false);
        const json = await resp.json();
        setSpotifyConnected(Boolean(json?.connected));
      } catch {
        setSpotifyConnected(false);
      }
    })();
  }, []);

  useEffect(() => {
    const unsub = onAuthStateChanged(getAuth(firebaseApp), (u) => setAppUserId(u?.uid ?? null));
    return () => unsub();
  }, []);

  useEffect(() => {
    if (!audioRef.current) return;
    if (isPlaying) {
      audioRef.current.play();
    } else {
      audioRef.current.pause();
    }
  }, [isPlaying]);

  const handleTimeUpdate = () => {
    if (audioRef.current) {
      setCurrentTime(audioRef.current.currentTime);
    }
  };

  const handleSeek = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = Number(e.target.value);
    if (audioRef.current) {
      audioRef.current.currentTime = value;
      setCurrentTime(value);
    }
  };

  const formatTime = (s: number) =>
    `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

  return (
    <Card className="p-8">
      <div className="flex flex-col items-center text-center space-y-6">
        <div className="relative">
          {albumArt ? (
            <img 
              src={albumArt} 
              alt={album} 
              className="w-80 h-80 rounded-lg object-cover shadow-2xl"
            />
          ) : (
            <div className="w-80 h-80 rounded-lg bg-muted flex items-center justify-center">
              <Music className="h-32 w-32 text-muted-foreground" />
            </div>
          )}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="bg-primary/20 backdrop-blur-sm rounded-full p-6 animate-pulse">
              <Pause className="h-16 w-16 text-primary" />
            </div>
          </div>
        </div>
        
        <div className="space-y-2 max-w-xl">
          <h2 className="text-4xl font-bold" data-testid="text-now-playing-title">
            {title}
          </h2>
          <p className="text-2xl text-foreground/70" data-testid="text-now-playing-artist">
            {artist}
          </p>
          {album && (
            <p className="text-sm text-muted-foreground">{album}</p>
          )}
        </div>

        {previewUrl ? (
          <div className="w-full max-w-md flex flex-col items-center gap-2">
            <audio
              ref={audioRef}
              src={previewUrl}
              onTimeUpdate={handleTimeUpdate}
              onLoadedMetadata={() => {
                if (audioRef.current) setDuration(audioRef.current.duration || 30);
              }}
              onEnded={() => setIsPlaying(false)}
              autoPlay
            />
            <div className="flex items-center gap-2 w-full">
              <button
                onClick={() => setIsPlaying((p) => !p)}
                className="px-2 py-1 rounded bg-accent"
              >
                {isPlaying ? "Pause" : "Play"}
              </button>
              {/* Play on performer's Spotify */}
              {spotifyConnected ? (
                <PlayButton spotifyUri={spotifyUri} appUserId={appUserId} />
              ) : (
                <a href={appUserId ? `/api/spotify/login?userId=${encodeURIComponent(appUserId)}` : `/api/spotify/login`} className="px-2 py-1 rounded bg-foreground/10 text-sm">Connect Spotify</a>
              )}
              <span className="text-xs w-10 text-right">{formatTime(currentTime)}</span>
              <input
                type="range"
                min={0}
                max={duration}
                value={currentTime}
                onChange={handleSeek}
                className="flex-1 accent-primary"
                step={0.01}
              />
              <span className="text-xs w-10">{formatTime(duration)}</span>
            </div>
          </div>
        ) : (
          <div className="text-muted-foreground text-sm">
            No preview available for this song.
          </div>
        )}
      </div>
    </Card>
  );
}

function PlayButton({ spotifyUri, appUserId }: { spotifyUri?: string; appUserId?: string | null }) {
  const { toast } = useToast();
  return (
    <button
      onClick={async () => {
        try {
          const body: any = {};
          if (spotifyUri) body.uri = spotifyUri;
          else return;
          if (appUserId) body.userId = appUserId;
          const resp = await fetch(`/api/spotify/play`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
          if (resp.ok) {
            toast({ title: "Playing on Spotify", description: "Attempting to play on performer Spotify account" });
          } else {
            const json = await resp.json().catch(() => ({}));
            const desc = typeof json?.error === "string" ? json.error : JSON.stringify(json?.error ?? json ?? "Could not start playback");
            toast({ title: "Spotify play failed", description: desc, variant: "destructive" });
          }
        } catch (e: any) {
          const desc = typeof e?.message === "string" ? e.message : JSON.stringify(e ?? String(e));
          toast({ title: "Spotify play error", description: desc, variant: "destructive" });
        }
      }}
      className="px-2 py-1 rounded bg-spotify text-white"
    >
      Play on Spotify
    </button>
  );
}
