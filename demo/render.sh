#!/usr/bin/env bash
# Turns the recorded take into demo/out/demo.mp4: captions.jsonl becomes an SRT,
# the SRT is burned into the webm, and a title and an end card are glued on.
#
#   ./render.sh                 newest webm in out/, cards, burned subtitles
#   ./render.sh --no-cards      body only
#   ./render.sh --srt-only      rebuild out/demo.srt and stop
#   ./render.sh --max-step 20   cut steps longer than 20s down to head plus tail
#   ./render.sh --keep-waits    keep every second, including the sign-in wait
#   ./render.sh --music bed.mp3 lay a music bed under it, looped and faded
#   ./render.sh out/abc123.webm pick the take by hand
set -euo pipefail
unset CDPATH  # with CDPATH set, cd echoes its target and $(cd .. && pwd) returns it twice

here=$(cd -- "$(dirname -- "$0")" && pwd)
out=$here/out

cards=1
srt_only=0
src=""
# A step that waits on a human runs for minutes with a still screen. Anything
# longer than this keeps its head and tail and loses the middle.
max_step=20
head_keep=4
tail_keep=2
music=""
# Background music under nothing but subtitles. Quiet enough to ignore, present
# enough to carry two minutes without a voiceover.
music_db=-18
# A bed shorter than the film has to loop, and most tracks fade out at their own
# end, which puts a dip in the middle of the film. Dropping the outro first makes
# the loop join on steady material instead.
music_trim=0
music_out=demo.mp4
while [ $# -gt 0 ]; do
	case $1 in
	--no-cards) cards=0 ;;
	--srt-only) srt_only=1 ;;
	--keep-waits) max_step=0 ;;
	--music)
		shift
		music=${1:?--music wants an audio file}
		;;
	--music-db)
		shift
		music_db=${1:?--music-db wants a number, for example -18}
		;;
	--music-trim)
		shift
		music_trim=${1:?--music-trim wants seconds to drop from the end of the bed}
		;;
	--music-out)
		shift
		music_out=${1:?--music-out wants a filename}
		;;
	--max-step)
		shift
		max_step=${1:?--max-step wants seconds}
		;;
	-h | --help)
		sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	-*)
		echo "unknown option: $1" >&2
		exit 2
		;;
	*) src=$1 ;;
	esac
	shift
done

need() { command -v "$1" >/dev/null || { echo "$1 is not on PATH" >&2; exit 1; }; }
need ffmpeg
need ffprobe
need node

captions=$out/captions.jsonl
srt=$out/demo.srt
[ -f "$captions" ] || { echo "no $captions, record a take first" >&2; exit 1; }

if [ -z "$src" ]; then
	# shellcheck disable=SC2012  # Playwright names its videos from a hash, no newlines to trip over
	src=$(ls -1t "$out"/*.webm 2>/dev/null | head -n1) || true
	[ -n "$src" ] || { echo "no .webm in $out, record a take first" >&2; exit 1; }
fi
[ -f "$src" ] || { echo "no such file: $src" >&2; exit 1; }
src=$(cd -- "$(dirname -- "$src")" && pwd)/$(basename -- "$src")

# The cut has to happen before the SRT is written, because every caption after a
# cut moves back by what was removed.
trimfilter=""
if [ "$max_step" != 0 ] && [ -f "$here/trim.py" ]; then
	dur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$src")
	trimfilter=$(python3 "$here/trim.py" "$captions" "$out/captions-trimmed.jsonl" \
		"$max_step" "$head_keep" "$tail_keep" "$dur") || true
	[ -n "$trimfilter" ] && captions=$out/captions-trimmed.jsonl
fi

# node rather than a shell JSON parser: demo.mjs already requires it, and
# JSON.parse gets the escapes right.
node - "$captions" "$srt" <<'NODEJS'
const fs = require("node:fs");
const [src, dst] = process.argv.slice(2);

// captions.jsonl is meant to be hand-edited between renders, so a typo in it is
// a normal thing to hit. Say what is wrong on one line instead of a node stack.
const fail = (m) => { process.stderr.write("render.sh: " + m + "\n"); process.exit(1); };

const ts = (ms) => {
  ms = Math.max(0, Math.round(ms));
  const p = (n, w) => String(n).padStart(w, "0");
  return p(Math.floor(ms / 3600000), 2) + ":" + p(Math.floor(ms / 60000) % 60, 2) +
    ":" + p(Math.floor(ms / 1000) % 60, 2) + "," + p(ms % 1000, 3);
};

// libass reads { and } as override tags, so a caption quoting a folder template
// such as {yyyy} would render as nothing at all. Backslashes come through as
// they are, which is what a UNC path in a caption needs.
// ponytail: \n \N \h stay ASS escapes. German prose does not produce them.
const esc = (t) => t.replace(/[{}]/g, "\\$&")
  .split(/\r?\n/).map((s) => s.trim()).filter(Boolean).join("\n");

const cues = fs.readFileSync(src, "utf8").split("\n")
  .map((l) => l.trim()).filter(Boolean)
  .map((l, i) => {
    try { return JSON.parse(l); } catch (e) {
      fail("captions.jsonl line " + (i + 1) + " is not JSON: " + e.message);
    }
  })
  // start and end are milliseconds from the first video frame. A hand-edited
  // line missing one would otherwise reach ts() and produce a NaN timestamp.
  .filter((c) => c && typeof c.text === "string" && c.text.trim() !== "" &&
    Number.isFinite(c.start) && Number.isFinite(c.end))
  .sort((a, b) => a.start - b.start);

let n = 0;
const lines = [];
for (let i = 0; i < cues.length; i++) {
  const c = cues[i];
  const next = cues[i + 1];
  // libass stacks overlapping cues on top of each other, which reads as a mess.
  const end = next && c.end > next.start ? next.start : c.end;
  if (!(end > c.start)) continue;
  lines.push(String(++n), ts(c.start) + " --> " + ts(end), esc(c.text), "");
}
if (!n) fail("no usable captions in " + src + ". Each line needs start, end and text.");
fs.writeFileSync(dst, lines.join("\n"));
process.stderr.write(n + " captions -> " + dst + "\n");
NODEJS

if [ "$srt_only" = 1 ]; then exit 0; fi

read -r W H < <(ffprobe -v error -select_streams v:0 \
	-show_entries stream=width,height -of csv=p=0 "$src" | tr ',' ' ') || true
[ -n "${W:-}" ] && [ -n "${H:-}" ] || { echo "no video stream in $src" >&2; exit 1; }

# Playwright writes a variable frame rate, so the body is forced to a constant
# one. It has to match the cards or the concat demuxer refuses the copy.
fps=25

# force_style is measured in the ASS script resolution, and ffmpeg's SRT reader
# hardcodes that to 384x288 no matter how big the video is. Everything below is
# a pixel intent converted into those units, so the styling survives a take
# recorded at another size.
#
# MarginL clears the 224px navigation rail, so a long caption never sits on top
# of it. BorderStyle=3 with a translucent OutlineColour is the band; the product
# background #0b0d10 at 85% keeps it readable over the lighter cards.
style=$(awk -v w="$W" -v h="$H" 'BEGIN{
	printf "FontName=DejaVu Sans,FontSize=%.2f,PrimaryColour=&H00efe9e6,OutlineColour=&H26100d0b,BackColour=&H26100d0b,BorderStyle=3,Outline=%.2f,Shadow=0,Alignment=2,MarginL=%.2f,MarginR=%.2f,MarginV=%.2f",
		26*288/h, 10*288/h, 248*384/w, 64*384/w, 44*288/h
}')

# Identical across every segment, because the concat demuxer copies streams and
# a mismatched SPS is what makes the result unplayable halfway through.
x264=(-c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -profile:v high -level 40
	-color_primaries bt709 -color_trc bt709 -colorspace bt709 -an)

echo "take     $src (${W}x${H})"
echo "encoding the body once: VP8 to H.264 with the subtitles burned in"

# cd into out/ so the subtitles filter gets a plain relative filename. The path
# lives inside a filtergraph, where a colon or a backslash in a directory name
# would be read as syntax.
if [ -n "$trimfilter" ]; then
	(cd "$out" && ffmpeg -y -hide_banner -loglevel warning \
		-i "$src" \
		-filter_complex "$trimfilter;[trimmed]fps=$fps,subtitles=demo.srt:force_style='$style'[v]" \
		-map "[v]" "${x264[@]}" -movflags +faststart body.mp4)
else
	(cd "$out" && ffmpeg -y -hide_banner -loglevel warning \
		-i "$src" \
		-vf "fps=$fps,subtitles=demo.srt:force_style='$style'" \
		"${x264[@]}" -movflags +faststart body.mp4)
fi

if [ "$cards" = 0 ]; then
	mv "$out/body.mp4" "$out/demo.mp4"
else
	echo "encoding the cards, then concatenating by stream copy"
	# drawtext's fontsize takes no expression, and drawbox's w and h mean the box
	# rather than the frame, so every number is worked out here instead.
	read -r f1 f2 rw rh rx ry < <(awk -v w="$W" -v h="$H" 'BEGIN{
		rw = int(w*0.05); rh = int(h*0.004); if (rh < 2) rh = 2
		printf "%d %d %d %d %d %d\n", h*0.075, h*0.032, rw, rh, (w-rw)/2, h/2+h*0.015
	}')
	card() { # duration, filter chain, output
		ffmpeg -y -hide_banner -loglevel warning \
			-f lavfi -i "color=c=0x0b0d10:s=${W}x${H}:r=$fps:d=$1" \
			-vf "$2" "${x264[@]}" "$out/$3"
	}
	card 3 "drawtext=font=DejaVu Sans:text='M365 Cloud Scan':fontcolor=0xe6e9ef:fontsize=$f1:x=(w-text_w)/2:y=(h-text_h)/2-h*0.06,\
drawbox=x=$rx:y=$ry:w=$rw:h=$rh:color=0xf6a935:t=fill,\
drawtext=font=DejaVu Sans:text='Einrichtung einer Box':fontcolor=0xf6a935:fontsize=$f2:x=(w-text_w)/2:y=h/2+h*0.055" \
		title.mp4
	card 2.5 "drawtext=font=DejaVu Sans:text='M365 Cloud Scan':fontcolor=0xe6e9ef:fontsize=$f1:x=(w-text_w)/2:y=(h-text_h)/2" \
		end.mp4

	printf "file '%s'\n" title.mp4 body.mp4 end.mp4 >"$out/concat.txt"
	if ! (cd "$out" && ffmpeg -y -hide_banner -loglevel warning \
		-f concat -safe 0 -i concat.txt -c copy -movflags +faststart demo.mp4); then
		echo "stream copy refused the segments, re-encoding the concatenation" >&2
		(cd "$out" && ffmpeg -y -hide_banner -loglevel warning \
			-f concat -safe 0 -i concat.txt "${x264[@]}" -movflags +faststart demo.mp4)
	fi
	rm -f "$out/title.mp4" "$out/end.mp4" "$out/body.mp4" "$out/concat.txt"
fi

if [ -n "$music" ]; then
	[ -f "$music" ] || { echo "no such audio file: $music" >&2; exit 1; }
	dur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$out/demo.mp4")
	[ "$music_out" != demo.mp4 ] || music_out=demo-music.mp4
	fade_out=$(awk -v d="$dur" 'BEGIN{printf "%.3f", (d > 3 ? d - 3 : 0)}')
	echo "adding the music bed at ${music_db} dB, fading out from ${fade_out}s"
	# The video is finished, so copy it and only encode the audio. -stream_loop
	# repeats a bed shorter than the film; -shortest cuts a longer one.
	bed=$music
	if [ "$music_trim" != 0 ]; then
		blen=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$music")
		keep=$(awk -v b="$blen" -v t="$music_trim" 'BEGIN{printf "%.3f", b - t}')
		echo "dropping the last ${music_trim}s of the bed so the loop joins on steady material"
		ffmpeg -y -v error -i "$music" -t "$keep" -c:a libmp3lame -q:a 2 "$out/bed-trimmed.mp3"
		bed=$out/bed-trimmed.mp3
	fi
	ffmpeg -y -hide_banner -loglevel warning \
		-i "$out/demo.mp4" -stream_loop -1 -i "$bed" \
		-filter_complex "[1:a]volume=${music_db}dB,afade=t=in:st=0:d=2,afade=t=out:st=${fade_out}:d=3[a]" \
		-map 0:v -map "[a]" -c:v copy -c:a aac -b:a 160k -shortest \
		-movflags +faststart "$out/$music_out"
	rm -f "$out/bed-trimmed.mp3"
fi

# $out/ has to stay inside the expansion, or an empty $music leaves final as the
# bare directory and the :- default below never fires.
final=${music:+$out/$music_out}
final=${final:-$out/demo.mp4}
ffprobe -v error -show_entries format=duration \
	-show_entries stream=codec_name,width,height,pix_fmt,avg_frame_rate \
	-of default=noprint_wrappers=1 "$final"
echo "wrote $final"
