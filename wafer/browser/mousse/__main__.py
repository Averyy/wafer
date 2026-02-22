"""Launch the Mousse recording server.

Usage:
    python -m wafer.browser.mousse [--port PORT]
"""

import argparse
import webbrowser

from wafer.browser.mousse._server import run_server


def main() -> None:
    parser = argparse.ArgumentParser(description="Mousse mouse recorder")
    parser.add_argument(
        "--port", type=int, default=8377, help="Server port",
    )
    args = parser.parse_args()

    url = f"http://localhost:{args.port}"
    print(f"Starting Mousse at {url}")
    webbrowser.open(url)
    run_server(args.port)


main()
