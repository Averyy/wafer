"""Browser-based challenge solving via patchright (patched Playwright)."""

from email.utils import formatdate

from wafer.browser._recaptcha_grid import (
    preflight_recaptcha_models,
    preload_recaptcha_models,
)
from wafer.browser._solver import (
    BrowserSolver,
    CapturedResponse,
    HardenedLaunch,
    InterceptResult,
    SolveResult,
    hardened_launch_config,
    scrub_headless_ua,
)


def format_cookie_str(cookie: dict) -> str:
    """Convert a browser cookie dict to a Set-Cookie header string.

    Input format (patchright/Playwright context.cookies()):
        {"name": str, "value": str, "domain": str, "path": str,
         "expires": float, "httpOnly": bool, "secure": bool,
         "sameSite": str}
    """
    parts = [f"{cookie['name']}={cookie['value']}"]
    domain = cookie.get("domain", "")
    # Chromium reports Domain cookies with a leading dot and host-only cookies
    # without one. Omitting Domain for the latter preserves host-only scope when
    # the cookie is imported into the transport jar.
    if domain.startswith("."):
        parts.append(f"Domain={domain}")
    if cookie.get("path"):
        parts.append(f"Path={cookie['path']}")
    expires = cookie.get("expires", -1)
    if isinstance(expires, (int, float)) and expires > 0:
        parts.append(
            f"Expires={formatdate(expires, usegmt=True)}"
        )
    if cookie.get("secure"):
        parts.append("Secure")
    if cookie.get("httpOnly"):
        parts.append("HttpOnly")
    same_site = cookie.get("sameSite", "")
    if same_site and same_site != "":
        parts.append(f"SameSite={same_site}")
    return "; ".join(parts)


__all__ = [
    "BrowserSolver",
    "CapturedResponse",
    "HardenedLaunch",
    "InterceptResult",
    "SolveResult",
    "format_cookie_str",
    "hardened_launch_config",
    "preflight_recaptcha_models",
    "preload_recaptcha_models",
    "scrub_headless_ua",
]
