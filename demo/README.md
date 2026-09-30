# demo

Records a video of setting a box up: connect the tenant, create a share, build a
destination, wire the route, watch a scan reach SharePoint. German interface,
German subtitles, one continuous take.

Nothing in here is part of the product build. `demo/out/` and `demo/node_modules/`
are ignored by git.

| file | what it does |
| --- | --- |
| `demo.mjs` | drives the browser and writes `out/demo.webm` and `out/captions.jsonl` |
| `render.sh` | turns those two into `out/demo.mp4` with burned-in subtitles and cards |
| `reset.sh` | wipes the Vagrant box so the next take starts from nothing |

## Prerequisites

**Node modules.** `cd demo && npm install`. Only `playwright-core` is needed, and
only for the recording half.

**Chromium.** Playwright's own browser download does not run on NixOS. The system
chromium works:

    CHROMIUM_BIN=$(command -v chromium) node demo.mjs

`demo.mjs` defaults to `/etc/profiles/per-user/acid/bin/chromium` if the variable
is unset.

**ffmpeg where Playwright expects it.** Playwright encodes the screen recording
with an ffmpeg binary it downloads itself, and that download fails on NixOS the
same way the browser one does. It looks for exactly one path, so point it at the
system build:

    mkdir -p ~/.cache/ms-playwright/ffmpeg-1011
    ln -s "$(command -v ffmpeg)" ~/.cache/ms-playwright/ffmpeg-1011/ffmpeg-linux

Do this before the first take. Playwright only reaches for the encoder when the
browser context closes, so a missing symlink throws away a recording that has
already been made. The `1011` in the path is tied to the installed
`playwright-core`; after an upgrade, check what it asks for and relink.

**ffmpeg and ffprobe on PATH** for `render.sh`, with libass, drawtext and
libx264. Node is used there too, to read `captions.jsonl`.

## A take

The box under test on this workstation is `https://127.0.0.1:8445`, started by
`scripts/dev.sh`, which prints its admin password into `.dev-run.log`. That box
cannot create a share. The Vagrant VM at `https://192.168.121.10:8444` can, so a
real take runs against that one:

    cd demo
    ./reset.sh --yes
    node demo.mjs --url https://192.168.121.10:8444
    ./render.sh

`demo.mjs` finds the admin password on its own from `.dev-run.log`, or takes
`--password`, or `SCAN_ADMIN_PASSWORD`. The Vagrant password is printed by
`vagrant up` at the end of provisioning.

`render.sh` picks the newest `.webm` in `out/`, so it needs no arguments. Pass a
path to pick an older take by hand.

## The one manual moment

Tenant onboarding uses the Microsoft device-code flow, and a human does that part
while the recording keeps rolling. Nothing automates the Microsoft login page and
no Microsoft credential goes near either script.

`demo.mjs` stops at that point and prints the code and the URL in a box on the
terminal. The operator opens the URL on a machine where they can sign in as a
tenant admin, enters the code, and accepts the consent prompt. The script polls
the box until the sign-in lands, then carries on with site selection and the rest
of the take. It waits ten minutes. If the code expires, stop with Ctrl-C and
start the run again; a new code is issued every time.

Have the browser window with the Microsoft page ready before starting, and sign
out of any account you do not want on screen. That window is not recorded, but
the tenant it picks is.

## Between takes

    ./reset.sh --yes

Over ssh into the Vagrant VM: stop the service, delete `state.json`,
`settings.json` and `tenant.json` from `/var/lib/m365-scan`, empty the quarantine
and progress directories, remove every share directory under `/srv/m365-scan`,
drop the shares and their SMB accounts out of the Samba registry, start the
service again. The admin password survives; the tenant does not, because
re-onboarding is the first thing the video shows.

It refuses to run without `--yes`. There is no undo.

## Re-rendering subtitles without re-recording

The caption text lives in `out/captions.jsonl`, one JSON object per line with the
fields `start`, `end` and `text`. The two times are milliseconds from the first
video frame. A line missing any of the three is dropped, and a render with no
usable line left says so and stops. Edit it and run:

    ./render.sh --srt-only    # rebuild out/demo.srt and stop, to read it over
    ./render.sh               # burn it into the same take again

`--no-cards` leaves the title and end card off, which is quicker while iterating
on wording. Both re-use the recorded webm; nothing has to be shot again.

Two things worth knowing about the styling. libass reads `{` and `}` as override
tags, so a caption quoting a folder template such as `{yyyy}/{MM}` is escaped on
the way into the SRT and shows up as typed. And the subtitle band sits clear of
the 224px navigation rail, so a long caption never lands on the sidebar.

## What ends up on screen

The take is shot against a real tenant, and none of it is blurred:

- the tenant domain, in the Settings page and in the connection dialog
- the SharePoint site and document library names in the destination picker
- the Microsoft device code, for as long as it is on screen
- the share's SMB password, which the box shows once after creating the share

The device code is dead within minutes and the code alone grants nothing. The
share password is the one thing that outlives the recording. If the box in the
video is thrown away afterwards, nothing needs doing. If it stays in service,
rotate that password from the share detail page once the take is in the can, and
enter the new one on the MFP.

## Dead air

A take is one continuous recording, so the Microsoft sign-in sits in the middle
of it for as long as the human takes. `render.sh` cuts that out: any step longer
than 20 seconds keeps its first 8 and its last 5, loses the middle, and every
caption after the cut moves back by what was removed. Nothing moves on screen
during the wait, so the join is invisible.

```
./render.sh                 cut long waits, the default
./render.sh --max-step 40   only cut what runs past 40 seconds
./render.sh --keep-waits    keep every second, warts and all
```

## Music

There is no voiceover, so a quiet bed carries the two minutes. Any audio file
works; it is looped if shorter than the film, cut if longer, faded in over two
seconds and out over the last three.

```
./render.sh --music bed.mp3
./render.sh --music bed.mp3 --music-db -14   louder, the default is -18
```

The video is already encoded at that point, so this pass copies the picture and
encodes only the audio.

Sources whose licence survives a customer-facing video: Pixabay Music (no
attribution), the Free Music Archive filtered to CC0 or CC-BY, Incompetech
(CC-BY, so credit it), the YouTube Audio Library, or a paid library such as
Artlist if this becomes a series. Check the licence on the track page, since
these sites host mixed terms.

Restrained minimal electronic suits the material: steady pulse, no vocals, no
build and drop, 90 to 110 BPM. The viewer is reading subtitles, so a melody
strong enough to follow works against the film.
