"""Render the README demo as an animated GIF.

Reproducible on purpose: the frames come from actually running ARKEXA against
tools/demo, not from a screenshot someone touched up. If the output format
changes, rerun this and the README is correct again.

    python tools/make_demo.py

Needs Pillow and ffmpeg. Writes docs/demo.gif.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

DEMO = ROOT / "tools" / "demo"
OUT = ROOT / "docs" / "demo.gif"

# A dark, neutral terminal. Not anyone's brand colours.
BACKGROUND = (13, 17, 23)
CHROME = (22, 27, 34)
BORDER = (48, 54, 61)
DEFAULT = (201, 209, 217)
DIM = (110, 118, 129)
PROMPT = (63, 185, 80)
COMMAND = (201, 209, 217)

ANSI_COLORS = {
    "1;31": (248, 81, 73),
    "1;33": (210, 153, 34),
    "1;36": (57, 197, 207),
    "1;37": (201, 209, 217),
    "2": DIM,
}

FONT_CANDIDATES = [
    r"C:\Windows\Fonts\CascadiaCode.ttf",
    r"C:\Windows\Fonts\consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]

FONT_SIZE = 15
LINE_HEIGHT = 21
PAD_X = 18
PAD_Y = 14
TITLE_H = 30
ANSI_RE = re.compile(r"\033\[([0-9;]*)m")


def load_font() -> ImageFont.FreeTypeFont:
    for candidate in FONT_CANDIDATES:
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, FONT_SIZE)
    return ImageFont.load_default()


def capture() -> list[str]:
    """Run ARKEXA for real and keep the colour codes."""
    environment = dict(os.environ, FORCE_COLOR="1", PYTHONPATH=str(ROOT / "src"))
    finished = subprocess.run(
        [sys.executable, "-m", "arkexa", str(DEMO)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
        cwd=str(ROOT),
    )
    return finished.stdout.rstrip("\n").split("\n")


def spans(line: str) -> list[tuple[str, tuple[int, int, int]]]:
    """Split an ANSI line into (text, colour) runs."""
    result: list[tuple[str, tuple[int, int, int]]] = []
    colour = DEFAULT
    position = 0
    for match in ANSI_RE.finditer(line):
        if match.start() > position:
            result.append((line[position : match.start()], colour))
        code = match.group(1)
        colour = DEFAULT if code in ("", "0") else ANSI_COLORS.get(code, colour)
        position = match.end()
    if position < len(line):
        result.append((line[position:], colour))
    return result


def visible(line: str) -> str:
    return ANSI_RE.sub("", line)


def render(lines: list[str], command: str, width: int, height: int, font) -> Image.Image:
    image = Image.new("RGB", (width, height), BACKGROUND)
    draw = ImageDraw.Draw(image)

    draw.rectangle([0, 0, width, TITLE_H], fill=CHROME)
    draw.line([(0, TITLE_H), (width, TITLE_H)], fill=BORDER)
    for index, colour in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([14 + index * 18, 11, 22 + index * 18, 19], fill=colour)

    y = TITLE_H + PAD_Y
    draw.text((PAD_X, y), "$", font=font, fill=PROMPT)
    draw.text((PAD_X + 16, y), command, font=font, fill=COMMAND)
    y += LINE_HEIGHT

    for line in lines:
        x = PAD_X
        for text, colour in spans(line):
            draw.text((x, y), text, font=font, fill=colour)
            x += draw.textlength(text, font=font)
        y += LINE_HEIGHT
    return image


def main() -> int:
    if shutil.which("ffmpeg") is None:
        print("ffmpeg is not on PATH")
        return 1

    font = load_font()
    output = capture()
    if not output or not any(output):
        print("ARKEXA produced no output; is tools/demo still a vulnerable example?")
        return 1

    command = "arkexa ."
    probe = Image.new("RGB", (10, 10))
    measure = ImageDraw.Draw(probe)
    longest = max(measure.textlength(visible(line), font=font) for line in output)
    width = int(max(longest, measure.textlength(command, font=font) + 16) + PAD_X * 2)
    height = TITLE_H + PAD_Y * 2 + LINE_HEIGHT * (len(output) + 1)
    width += width % 2
    height += height % 2

    frames: list[tuple[Image.Image, int]] = []

    # Type the command.
    for index in range(len(command) + 1):
        frames.append((render([], command[:index], width, height, font), 6))
    frames.append((render([], command, width, height, font), 30))

    # Then reveal the report a line at a time, so the chain reads as a chain.
    for index in range(1, len(output) + 1):
        hold = 4 if output[index - 1].strip() else 2
        frames.append((render(output[:index], command, width, height, font), hold))
    frames.append((render(output, command, width, height, font), 400))

    with tempfile.TemporaryDirectory() as directory:
        listing = []
        for index, (frame, hold) in enumerate(frames):
            name = Path(directory) / f"f{index:04d}.png"
            frame.save(name)
            listing.append(f"file '{name.as_posix()}'\nduration {hold / 100:.2f}")
        listing.append(f"file '{name.as_posix()}'")
        concat = Path(directory) / "frames.txt"
        concat.write_text("\n".join(listing), encoding="utf-8")

        palette = Path(directory) / "palette.png"
        subprocess.run(
            ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(concat),
             "-vf", "palettegen=stats_mode=diff", str(palette)],
            check=True, capture_output=True,
        )
        OUT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(concat),
             "-i", str(palette), "-lavfi", "paletteuse=dither=bayer:bayer_scale=3",
             "-loop", "0", str(OUT)],
            check=True, capture_output=True,
        )

    size = OUT.stat().st_size
    print(f"wrote {OUT} ({size / 1024:.0f} KB, {len(frames)} frames, {width}x{height})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
