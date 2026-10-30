# AgentSec Ops demonstration

[Watch / download the MP4](agentsec-ops-demo.mp4)

[![Demo preview](demo-preview.png)](agentsec-ops-demo.mp4)

- Duration: **1 minute 58 seconds**.
- Video: H.264, 1600×900, 15 fps; audio: AAC narration.
- Content: actual fresh local-model execution, edited and rendered as a terminal replay.
- Narration: offline macOS synthetic voice, explicitly identified in the video.
- This is **not a desktop screen capture or the developer's recorded voice**.
- Commands, actual output, full traces, tests and the captured CI status are preserved in
  `results/demo-v1/`; the video manifest records hashes and the tested source commit.
- Five selected illustrative executions are shown, not a new performance benchmark.
  The separately labeled full-study figures come from the preserved 102-execution report.

The demo shows authorized support, an attacker-selected phrase reaching the baseline
response, containment of delivery while raw model hijacking persists, and an inventory
operation denied before execution. A real model response can vary when rerun.

The final MP4, preview, chapter captions (`.srt`), narration transcript and provenance
manifest are in this directory. FFmpeg fully decoded both media streams successfully;
the six result frames were inspected and the displayed results checked against the capture.

## Reproduce the capture

With the core environment installed, Ollama running and the existing model available:

```sh
mkdir -p results/demo-new
script -q results/demo-new/terminal.typescript .venv/bin/python scripts/capture_demo.py --output results/demo-new
```

The capture requires authenticated `gh` only for the read-only CI snapshot. It never sends
messages or uploads private desktop content. The data and tools are synthetic local fixtures.
Choose a new directory to preserve old capture evidence.

## Reproduce the optional media rendering

The renderer uses macOS fonts and `say`; media dependencies are separate from the core lock.
Install `scripts/requirements-demo.txt` in an optional environment, then supply an FFmpeg
executable (imageio-ffmpeg includes one):

```sh
python scripts/render_demo.py --capture results/demo-new --output docs/media/demo-new.mp4 --ffmpeg /absolute/path/to/ffmpeg
```

The renderer checks that the capture actually supports its displayed before/after claims.
If a fresh model run differs, it fails rather than silently generating a misleading video.
Narration is synthetic, pauses are shortened, and paths are abbreviated for readability.
The result is a recorded-execution replay suitable for a project demo, not evidence of
general model resistance, zero utility cost or production readiness.
