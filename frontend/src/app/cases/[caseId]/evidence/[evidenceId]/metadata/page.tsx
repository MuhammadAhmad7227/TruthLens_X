"use client";

import { useEffect, useState } from "react";
import { MetadataInspector } from "@/components/metadata/MetadataInspector";

type RecordShape = {
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

export default function MetadataPage({
  params,
}: {
  params: Promise<{ caseId: string; evidenceId: string }>;
}) {
  const [records, setRecords] = useState<RecordShape[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = async (caseId: string, evidenceId: string) => {
    const response = await fetch(
      `/api/v1/cases/${caseId}/evidence/${evidenceId}/metadata`,
      { cache: "no-store" },
    );
    if (!response.ok) throw new Error("Unable to load metadata");
    const data = (await response.json()) as { items: RecordShape[] };
    setRecords(data.items);
  };

  useEffect(() => {
    void params.then(({ caseId, evidenceId }) =>
      load(caseId, evidenceId).catch((cause: unknown) =>
        setError(cause instanceof Error ? cause.message : "Unable to load metadata"),
      ),
    );
  }, [params]);

  if (error) {
    return <main className="p-6"><p role="alert">{error}</p></main>;
  }

  return (
    <main className="mx-auto max-w-5xl p-6">
      <MetadataInspector records={records} />
    </main>
  );
}
