"""Launch the Mousse recording server.

Usage:
    python -m wafer.browser.mousse [--port PORT]
"""

import argparse
from pathlib import Path

from wafer.browser.mousse._server import run_server


def main() -> None:
    parser = argparse.ArgumentParser(description="Mousse mouse recorder")
    parser.add_argument(
        "--port", type=int, default=8377, help="Server port",
    )
    parser.add_argument(
        "--collected-det", type=Path,
        default=Path("training/recaptcha/collected_det"),
        help="Collected DET grids directory",
    )
    parser.add_argument(
        "--collected-cls", type=Path,
        default=Path("training/recaptcha/collected_cls"),
        help="Collected CLS tiles directory",
    )
    args = parser.parse_args()

    run_server(
        args.port,
        collected_det=args.collected_det,
        collected_cls=args.collected_cls,
    )


main()
