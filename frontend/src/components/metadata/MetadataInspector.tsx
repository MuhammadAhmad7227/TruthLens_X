"use client";

import { useMemo, useState } from "react";

type MetadataRecord = {
  id: string;
  extractor: string;
  extractor_version: string;
  invocation_args: Record<string, unknown>;
  raw_tags: Record<string, unknown>;
  normalised: Record<string, unknown>;
  stripping_signals: Record<string, unknown>;
  source_sha256: string;
  extracted_at: string;
};

type Props = {
  records: MetadataRecord[];
  onExtract?: () => Promise<void>;
};

export function MetadataInspector({ records, onExtract }: Props) {
  const [tab, setTab] = useState<"normalised" | "raw" | "diff">("normalised");
  const latest = records[0];

  const diff = useMemo(() => {
    if (records.length < 2) return {};
    const previous = records[1].normalised;
    const current = latest.normalised;
    const keys = new Set([...Object.keys(previous), ...Object.keys(current)]);
    return Object.fromEntries(
      [...keys]
        .filter((key) => JSON.stringify(previous[key]) !== JSON.stringify(current[key]))
        .map((key) => [key, { before: previous[key], after: current[key] }]),
    );
  }, [latest, records]);

  if (!latest) {
    return (
      <section className="rounded-lg border p-6">
        <h2 className="text-lg font-semibold">Metadata</h2>
        <p className="mt-2 text-sm opacity-70">No metadata extraction is available yet.</p>
        {onExtract ? (
          <button
            className="mt-4 rounded-md border px-4 py-2 text-sm"
            onClick={() => void onExtract()}
          >
            Extract metadata
          </button>
        ) : null}
      </section>
    );
  }

  const value = tab === "normalised" ? latest.normalised : tab === "raw" ? latest.raw_tags : diff;

  return (
    <section className="rounded-lg border p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Metadata inspector</h2>
          <p className="text-xs opacity-70">
            {latest.extractor} {latest.extractor_version} · {new Date(latest.extracted_at).toLocaleString()}
          </p>
        </div>
        {onExtract ? (
          <button className="rounded-md border px-3 py-2 text-sm" onClick={() => void onExtract()}>
            Re-extract
          </button>
        ) : null}
      </div>
      <div className="mt-4 flex gap-2" role="tablist" aria-label="Metadata views">
        {(["normalised", "raw", "diff"] as const).map((name) => (
          <button
            key={name}
            role="tab"
            aria-selected={tab === name}
            className="rounded-md border px-3 py-1 text-sm"
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </div>
      <pre className="mt-4 max-h-[32rem] overflow-auto rounded-md border p-4 text-xs">
        {JSON.stringify(value, null, 2)}
      </pre>
      <p className="mt-3 break-all text-xs opacity-70">
        Source SHA-256: {latest.source_sha256}
      </p>
    </section>
  );
}
