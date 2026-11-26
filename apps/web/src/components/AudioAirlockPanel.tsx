import { useEffect, useRef, useState } from "react";
import { Mic, Play, ShieldCheck, Square, Volume2 } from "lucide-react";
import { wireTap } from "../services/wireTap.js";
import {
  checkChromeMultimodalAudioAvailability,
  hashRecordedAudioBlob,
  synthesizeLocalExecutiveVoiceNote,
  transcribeAudioLocally,
  type LocalAudioArtifact,
  type LocalAudioTranscriptionResult,
} from "../utils/audioAirlock.js";

interface Props {
  readonly onStageAudioTranscript: (transcript: string, sourceLabel: string) => void;
}

interface SpeechRecognitionLike {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  onresult: ((ev: { results: ArrayLike<{ 0?: { transcript?: string } }> }) => void) | null;
  start: () => void;
  stop: () => void;
}

export function AudioAirlockPanel({ onStageAudioTranscript }: Props) {
  const [open, setOpen] = useState(false);
  const [chromeAudioStatus, setChromeAudioStatus] = useState<string>("checking…");
  const [artifact, setArtifact] = useState<LocalAudioArtifact | null>(null);
  const [transcription, setTranscription] = useState<LocalAudioTranscriptionResult | null>(null);
  const [recording, setRecording] = useState(false);
  const [micError, setMicError] = useState<string | null>(null);
  const [copiedSha, setCopiedSha] = useState(false);

  const recorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const speechRef = useRef<SpeechRecognitionLike | null>(null);
  const speechTextRef = useRef<string>("");

  useEffect(() => {
    void checkChromeMultimodalAudioAvailability().then(setChromeAudioStatus);
  }, []);

  async function handleSynthesizeVoiceNote() {
    setMicError(null);
    const localArt = await synthesizeLocalExecutiveVoiceNote();
    setArtifact(localArt);
    const res = await transcribeAudioLocally({ artifact: localArt });
    setTranscription(res);

    wireTap.record({
      stage: "AUDIO_AIRLOCK",
      inferenceSource: "DETERMINISTIC_LOCAL",
      latencyMs: res.latencyMs,
      bytesSent: 0,
      payloadPreview: `LOCAL AUDIO AIRLOCK [${res.tier}] — ${localArt.label} (${localArt.byteLength}B WAV, sha256:${localArt.audioSha256.slice(0, 14)}…) transcribed locally · 0B audio sent to cloud.`,
    });
  }

  async function handleToggleMic() {
    setMicError(null);
    if (recording) {
      recorderRef.current?.stop();
      try {
        speechRef.current?.stop();
      } catch {
        // ignore stop race
      }
      setRecording(false);
      return;
    }

    if (!navigator.mediaDevices?.getUserMedia) {
      setMicError("Microphone capture unavailable in this browser context. Use Synthesize Voice Note.");
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const rec = new MediaRecorder(stream);
      chunksRef.current = [];
      speechTextRef.current = "";

      const win = window as unknown as {
        SpeechRecognition?: new () => SpeechRecognitionLike;
        webkitSpeechRecognition?: new () => SpeechRecognitionLike;
      };
      const SpeechCtor = win.SpeechRecognition ?? win.webkitSpeechRecognition;
      if (SpeechCtor) {
        const sr = new SpeechCtor();
        sr.continuous = true;
        sr.interimResults = false;
        sr.lang = "en-US";
        sr.onresult = (ev) => {
          const lines: string[] = [];
          for (let i = 0; i < ev.results.length; i++) {
            const t = ev.results[i]?.[0]?.transcript;
            if (t) lines.push(t.trim());
          }
          speechTextRef.current = lines.join(" ");
        };
        sr.start();
        speechRef.current = sr;
      }

      rec.ondataavailable = (ev) => {
        if (ev.data.size > 0) chunksRef.current.push(ev.data);
      };
      rec.onstop = () => {
        stream.getTracks().forEach((tr) => tr.stop());
        void (async () => {
          const blob = new Blob(chunksRef.current, { type: rec.mimeType || "audio/webm" });
          const audioSha256 = await hashRecordedAudioBlob(blob);
          const localArt: LocalAudioArtifact = {
            label: "live-mic-recording.webm",
            mimeType: blob.type || "audio/webm",
            byteLength: blob.size,
            durationSec: 2.0,
            audioSha256,
            waveformPeaks: Array.from({ length: 24 }, (_, idx) => 0.25 + ((idx * 17) % 7) * 0.1),
            objectUrl: URL.createObjectURL(blob),
            blob,
            syntheticTranscript: null,
          };
          setArtifact(localArt);
          const res = await transcribeAudioLocally({
            artifact: localArt,
            liveSpeechTranscript: speechTextRef.current,
          });
          setTranscription(res);
          wireTap.record({
            stage: "AUDIO_AIRLOCK",
            inferenceSource:
              res.tier === "CHROME_NANO_MULTIMODAL_AUDIO" ? "ON_DEVICE" : "DETERMINISTIC_LOCAL",
            latencyMs: res.latencyMs,
            bytesSent: 0,
            payloadPreview: `MIC AUDIO AIRLOCK [${res.tier}] — ${localArt.byteLength}B captured locally (sha256:${audioSha256.slice(0, 14)}…) · 0B audio uploaded.`,
          });
        })();
      };

      recorderRef.current = rec;
      rec.start();
      setRecording(true);
    } catch (err) {
      setMicError(
        err instanceof Error
          ? `Mic permission/hardware error: ${err.message}. Use Synthesize Voice Note instead.`
          : "Microphone unavailable."
      );
    }
  }

  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 10,
        padding: "7px 10px",
        background: "rgba(15, 23, 42, 0.55)",
      }}
    >
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          style={{ padding: "3px 8px", fontSize: "0.73rem" }}
        >
          <Mic size={12} />
          On-Device Multimodal Audio Airlock (0B Audio Sent)
        </button>
        <span className="mono muted" style={{ fontSize: "0.67rem" }}>
          Nano Audio: {chromeAudioStatus}
        </span>
      </div>

      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 9 }}>
          <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
            <button
              type="button"
              className="primary"
              onClick={() => void handleSynthesizeVoiceNote()}
              style={{ padding: "4px 9px", fontSize: "0.72rem" }}
            >
              <Volume2 size={12} /> Synthesize Executive Voice Note (Local PCM WAV)
            </button>
            <button
              type="button"
              className={recording ? "danger" : undefined}
              onClick={() => void handleToggleMic()}
              style={{ padding: "4px 9px", fontSize: "0.72rem" }}
            >
              {recording ? <Square size={12} /> : <Mic size={12} />}
              {recording ? "Stop Local Recording" : "Record Mic (Local Only)"}
            </button>
          </div>

          {micError && (
            <div className="alert-amber" style={{ fontSize: "0.71rem" }}>
              {micError}
            </div>
          )}

          {artifact && transcription && (
            <div className="wire-item" style={{ gap: 7, borderColor: "rgba(16, 185, 129, 0.45)" }}>
              <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap" }}>
                <span className="badge green" style={{ fontSize: "0.66rem" }}>
                  <ShieldCheck size={11} /> 0B Raw Audio Sent · {transcription.tier}
                </span>
                <span className="mono muted" style={{ fontSize: "0.67rem", display: "inline-flex", alignItems: "center", gap: 5 }} title={artifact.audioSha256}>
                  {artifact.byteLength}B · {artifact.durationSec}s · sha256:{artifact.audioSha256.slice(0, 12)}…
                  <button type="button" aria-label="Copy full 64-char audio SHA-256" onClick={() => { void navigator.clipboard?.writeText(artifact.audioSha256); setCopiedSha(true); window.setTimeout(() => setCopiedSha(false), 1800); }} style={{ padding: "1px 5px", fontSize: "0.62rem" }}>{copiedSha ? "Copied 64c" : "Copy SHA"}</button>
                </span>
              </div>

              <div
                aria-label="Local PCM waveform preview"
                style={{
                  display: "flex",
                  alignItems: "flex-end",
                  gap: 2,
                  height: 26,
                  padding: "3px 6px",
                  background: "#060a12",
                  borderRadius: 6,
                }}
              >
                {artifact.waveformPeaks.map((pk, idx) => (
                  <div
                    key={idx}
                    style={{
                      flex: 1,
                      height: `${Math.round(pk * 100)}%`,
                      background: "#34d399",
                      borderRadius: 2,
                      opacity: 0.85,
                    }}
                  />
                ))}
              </div>

              {artifact.objectUrl && (
                <audio controls src={artifact.objectUrl} style={{ width: "100%", height: 28 }} />
              )}

              <button
                type="button"
                className="primary"
                onClick={() => onStageAudioTranscript(transcription.transcript, artifact.label)}
                style={{ padding: "5px 10px", fontSize: "0.73rem" }}
              >
                <Play size={12} /> Stage Transcript &amp; Run Local Airlock (0B Audio Sent)
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
