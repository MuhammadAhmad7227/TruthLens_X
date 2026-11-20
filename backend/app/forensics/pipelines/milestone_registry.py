"""Complete M9-M18 pipeline catalogue and operational metadata."""

PIPELINE_CATALOGUE = {
    "M9": ["image.ela", "image.dqt", "image.phash", "image.copy_move", "image.face_regions"],
    "M10": ["doc.structure", "doc.revisions", "doc.attachments", "doc.ocr", "doc.ooxml"],
    "M11": ["audio.screen", "audio.asr", "audio.diarization", "audio.splice", "audio.synthetic"],
    "M12": ["video.screen", "video.frames", "video.shots", "video.temporal", "video.audio_extract"],
    "M13": ["detection.objects", "detection.tracks", "alpr.plate"],
    "M14": [
        "deepfake.frequency",
        "deepfake.face",
        "deepfake.temporal",
        "deepfake.audio",
        "deepfake.indicators",
    ],
    "M15": [
        "comparison.exact",
        "comparison.phash",
        "comparison.feature",
        "comparison.embedding",
        "comparison.metadata",
    ],
    "M16": ["graph.entities", "graph.edges", "timeline.assemble", "graph.export"],
    "M17": ["assistant.retrieve", "assistant.answer", "assistant.actions"],
    "M18": ["report.manifest", "report.generate", "report.verify"],
}


def all_pipelines() -> set[str]:
    return {p for values in PIPELINE_CATALOGUE.values() for p in values}
