#!/usr/bin/env python3
"""Record whichever iPhone Duo display is lit, switching on fold and unfold.

`simctl io recordVideo` records one display at a time, and a folded Duo shows
the app on its cover display (1) while an unfolded one shows it on the inner
display (3). This polls the display that is not being recorded and, when it
lights up, ends the current segment and starts one on that display.

    follow-displays.py <udid> <out-dir>
    follow-displays.py wait <udid> <cover|inner> <scratch-dir>

Writes `segment-NN-dD.mov` files and stops when `<out-dir>/stop` exists.
"""

import subprocess
import sys
import time
from pathlib import Path

COVER, INNER = 1, 3


def lit(udid: str, display: int, shot: Path) -> bool:
    """Whether the display shows anything; a dark display screenshots black."""
    result = subprocess.run(
        ["xcrun", "simctl", "io", udid, "screenshot", f"--display={display}", "--type=jpeg", str(shot)],
        capture_output=True,
    )
    if result.returncode != 0:
        return False
    out = subprocess.run(
        ["sips", "-Z", "32", "-s", "format", "bmp", str(shot), "--out", str(shot.with_suffix(".bmp"))],
        capture_output=True,
    )
    if out.returncode != 0:
        return False
    data = shot.with_suffix(".bmp").read_bytes()[54:]
    return sum(data) / max(len(data), 1) > 12


def record(udid: str, display: int, path: Path) -> subprocess.Popen:
    process = subprocess.Popen(
        ["xcrun", "simctl", "io", udid, "recordVideo", "--codec=h264", f"--display={display}", "--force", str(path)],
        stderr=subprocess.PIPE,
        text=True,
    )
    # Wait for the first frame so segments line up with what happened.
    assert process.stderr is not None
    for line in process.stderr:
        if "Recording started" in line:
            break
    return process


def stop(process: subprocess.Popen) -> None:
    process.send_signal(2)  # SIGINT finalizes the movie
    process.wait()


def wait_for(udid: str, display: int, scratch: Path) -> None:
    """Block until `display` is the lit one (the Duo was folded or unfolded)."""
    while not lit(udid, display, scratch):
        time.sleep(0.3)


def main() -> None:
    if sys.argv[1] == "wait":
        # follow-displays.py wait <udid> <cover|inner> <scratch-dir>
        display = COVER if sys.argv[3] == "cover" else INNER
        wait_for(sys.argv[2], display, Path(sys.argv[4]) / "wait.jpg")
        return
    udid, out = sys.argv[1], Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    shot = out / "probe.jpg"
    current = INNER if lit(udid, INNER, shot) else COVER
    index = 0
    recorder = record(udid, current, out / f"segment-{index:02}-d{current}.mov")
    print(f"recording display {current}", flush=True)
    while not (out / "stop").exists():
        other = INNER if current == COVER else COVER
        if lit(udid, other, shot):
            stop(recorder)
            current, index = other, index + 1
            recorder = record(udid, current, out / f"segment-{index:02}-d{current}.mov")
            print(f"switched to display {current}", flush=True)
        time.sleep(0.2)
    stop(recorder)


if __name__ == "__main__":
    main()
