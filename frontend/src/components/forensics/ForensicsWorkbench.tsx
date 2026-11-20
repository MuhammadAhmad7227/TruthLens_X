"use client";
import { useMemo, useState } from "react";

const milestones = [
["M9","Image Forensics"],["M10","Document Forensics"],["M11","Audio Forensics"],["M12","Video Forensics"],
["M13","Detection, Tracking & ALPR"],["M14","Deepfake Indicators"],["M15","Comparison & Similarity"],
["M16","Graph & Timeline"],["M17","AI Investigation Assistant"],["M18","Reports"],["M19","Admin & Monitoring"],
["M20","Security Hardening"],["M21","E2E, Performance & Release"],
] as const;

export function ForensicsWorkbench(){
 const [selected,setSelected]=useState("M9");
 const current=useMemo(()=>milestones.find(([id])=>id===selected)!,[selected]);
 return <main className="min-h-screen p-8">
  <header className="mb-8"><p className="text-sm opacity-60">TruthLens X</p><h1 className="text-3xl font-semibold">Forensics Workbench</h1><p className="mt-2 opacity-70">Evidence intelligence, analysis, verification and release controls.</p></header>
  <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-4">
   {milestones.map(([id,name])=><button key={id} onClick={()=>setSelected(id)} className={"rounded-xl border p-4 text-left transition "+(id===selected?"ring-2":"")}>
    <div className="text-xs opacity-60">{id}</div><div className="font-medium">{name}</div>
   </button>)}
  </div>
  <section className="mt-8 rounded-2xl border p-6">
   <div className="text-sm opacity-60">{current[0]}</div><h2 className="text-2xl font-semibold">{current[1]}</h2>
   <p className="mt-3 max-w-3xl opacity-70">Results remain advisory and require human verification. Original evidence bytes are never modified by analysis or annotation actions.</p>
   <div className="mt-6 grid gap-4 md:grid-cols-3">
    <div className="rounded-xl border p-4"><div className="text-sm opacity-60">Integrity</div><div className="mt-1 font-medium">Original protected</div></div>
    <div className="rounded-xl border p-4"><div className="text-sm opacity-60">Provenance</div><div className="mt-1 font-medium">Engine + version + SHA-256</div></div>
    <div className="rounded-xl border p-4"><div className="text-sm opacity-60">Verification</div><div className="mt-1 font-medium">Human review required</div></div>
   </div>
  </section>
 </main>;
}
