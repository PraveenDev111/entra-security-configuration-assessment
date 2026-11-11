#!/usr/bin/env python3
"""Builds ONE self-contained HTML file: the example dashboard page with the data of the newest runs embedded in it.

The file needs no runs folder and no web server, so it can be mailed or put on a share. It reads the same data as the normal
dashboard (it uses dashboard_data.build) but changes neither the page template nor the data file's format.

    python src/build_standalone_dashboard.py [--output-dir runs] [--output file.html] [--keep 3]

Default output: <output-dir>/dashboard_standalone.html (runs/ is not committed: the file holds client data).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import dashboard_data
import paths

TEMPLATE = paths.ROOT / "examples" / "dashboard" / "dashboard.html"

# the page loads a data file through a script tag; here the data is already in the page, so that load is replaced
LOADER = [
    ("  var src = new URLSearchParams(location.search).get('data') || '../../runs/dashboard_data.js';\n", ""),
    ("  $('dataPath').textContent = src;\n", ""),
    ("  s.src = src + (src.indexOf('?') < 0 ? '?' : '&') + 'v=' + Date.now();   // never serve an old cached data file\n", ""),
    ("  document.head.appendChild(s);\n", "  setTimeout(s.onload, 0);   // data is embedded in this file; start once the page script has finished\n"),
]


def build_html(data_js: str) -> str:
    html = TEMPLATE.read_text(encoding="utf-8").replace("\r\n", "\n")
    for old, new in LOADER:
        if old not in html:
            sys.exit(f"{TEMPLATE} has changed: could not find\n  {old.strip()}\nUpdate LOADER in {Path(__file__).name}.")
        html = html.replace(old, new, 1)
    payload = data_js.strip().replace("</", "<" + chr(92) + "/")   # a data value must never close the script tag
    marker = "<script>"
    if marker not in html:
        sys.exit(f"no <script> tag found in {TEMPLATE}")
    i = html.index(marker)
    return html[:i] + "<script>/* embedded data */\n" + payload + "\n</script>\n" + html[i:]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output-dir", default=None, help="folder with the company/run folders (default: runs in the project root, or SECUREIT_OUTPUT_DIR)")
    ap.add_argument("--output", default=None, help="html file to write (default: <output-dir>/dashboard_standalone.html)")
    ap.add_argument("--keep", type=int, default=3, help="newest runs per company to include (default: 3)")
    args = ap.parse_args(argv)
    out_dir = Path(args.output_dir) if args.output_dir else paths.output_dir()
    if not out_dir.is_dir():
        sys.exit(f"{out_dir} is not a folder")
    try:
        from entra_checks import CONTROL_PLANE_ROLES as cp  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        cp = set()
    data_file = dashboard_data.build(out_dir, args.keep, set(cp))   # refreshes dashboard_data.js, as every collection run does
    html = build_html(data_file.read_text(encoding="utf-8"))
    target = Path(args.output) if args.output else out_dir / "dashboard_standalone.html"
    target.write_text(html, encoding="utf-8")
    n = len(json.loads(data_file.read_text(encoding="utf-8").split("=", 1)[1].rstrip().rstrip(";"))["companies"])
    print(f"Wrote {target} ({target.stat().st_size // 1024} KB, {n} companies). Open it in a browser or share the single file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
