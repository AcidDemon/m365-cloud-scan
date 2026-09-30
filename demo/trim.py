#!/usr/bin/env python3
"""Cuts the dead air out of a take.

A step that waits on a human, above all the Microsoft sign-in, can run for
minutes with a static screen. Keeping it whole makes the video unwatchable;
cutting it entirely hides what the box was doing. So a long step keeps its head
and its tail and loses the middle, and every caption after the cut moves back by
what was removed.

Reads captions.jsonl, writes the trimmed captions and prints an ffmpeg
filter_complex on stdout. Prints nothing when no step is long enough to cut,
which is the caller's signal to render the take untouched.
"""
import json
import sys

def main():
    src, dst, max_s, head_s, tail_s, total_s = sys.argv[1], sys.argv[2], *map(float, sys.argv[3:7])
    caps = [json.loads(l) for l in open(src) if l.strip()]
    if not caps:
        sys.exit("no captions")

    keep, out, shift = [], [], 0.0
    cursor = 0.0
    for c in caps:
        start, end = c["start"] / 1000.0, c["end"] / 1000.0
        span = end - start
        if span > max_s:
            # head, then a jump cut, then tail. Nothing moves on screen during
            # the gap, so the cut is invisible apart from the clock.
            keep.append((cursor, start + head_s))
            keep.append((end - tail_s, end))
            removed = span - head_s - tail_s
            out.append({"start": int((start - shift) * 1000),
                        "end": int((start + head_s + tail_s - shift) * 1000),
                        "text": c["text"]})
            shift += removed
            cursor = end
        else:
            out.append({"start": int((start - shift) * 1000),
                        "end": int((end - shift) * 1000), "text": c["text"]})
    if not shift:
        return
    keep.append((cursor, total_s))

    merged = []
    for a, b in keep:
        if b - a < 0.04:
            continue
        if merged and a - merged[-1][1] < 0.04:
            merged[-1] = (merged[-1][0], b)
        else:
            merged.append((a, b))

    with open(dst, "w") as f:
        for c in out:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    parts = "".join(f"[0:v]trim={a:.3f}:{b:.3f},setpts=PTS-STARTPTS[v{i}];"
                    for i, (a, b) in enumerate(merged))
    joins = "".join(f"[v{i}]" for i in range(len(merged)))
    print(f"{parts}{joins}concat=n={len(merged)}:v=1:a=0[trimmed]")
    print(f"cut {shift:.1f}s of waiting from {len(caps)} steps", file=sys.stderr)

main()
