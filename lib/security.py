"""Shared security helpers for input validation.

Used by video_downloader (SSRF), video_compose (FFmpeg filter injection),
and other tools that handle user/agent-provided paths and URLs.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# URL validation — SSRF defense for video_downloader and similar tools
# ---------------------------------------------------------------------------

# Domains that are legitimately downloadable via yt-dlp.
# This is an allowlist — anything NOT matching is rejected.
_ALLOWED_URL_DOMAINS = re.compile(
    r"^("
    r"(?:[a-z0-9-]+\.)*youtube\.com"
    r"|(?:[a-z0-9-]+\.)*youtu\.be"
    r"|(?:[a-z0-9-]+\.)*googlevideo\.com"
    r"|(?:[a-z0-9-]+\.)*vimeo\.com"
    r"|(?:[a-z0-9-]+\.)*tiktok\.com"
    r"|(?:[a-z0-9-]+\.)*instagram\.com"
    r"|(?:[a-z0-9-]+\.)*twitter\.com"
    r"|(?:[a-z0-9-]+\.)*x\.com"
    r"|(?:[a-z0-9-]+\.)*facebook\.com"
    r"|(?:[a-z0-9-]+\.)*dailymotion\.com"
    r"|(?:[a-z0-9-]+\.)*twitch\.tv"
    r"|(?:[a-z0-9-]+\.)*pexels\.com"
    r"|(?:[a-z0-9-]+\.)*pixabay\.com"
    r"|(?:[a-z0-9-]+\.)*unsplash\.com"
    r"|(?:[a-z0-9-]+\.)*archive\.org"
    r"|(?:[a-z0-9-]+\.)*wikimedia\.org"
    r"|(?:[a-z0-9-]+\.)*soundcloud\.com"
    r"|(?:[a-z0-9-]+\.)*bilibili\.com"
    r"|(?:[a-z0-9-]+\.)*openverse\.org"
    r"|(?:[a-z0-9-]+\.)*freesound\.org"
    r")$",
    re.IGNORECASE,
)


def validate_download_url(url: str) -> tuple[bool, str]:
    """Validate a URL before passing it to yt-dlp or similar downloaders.

    Returns (is_valid, reason). When is_valid is False, reason explains why.
    """
    if not url or not isinstance(url, str):
        return False, "URL boş veya geçersiz tip"

    parsed = urlparse(url.strip())

    # Scheme check — only http/https
    if parsed.scheme not in ("http", "https"):
        return False, f"İzin verilmeyen şema: '{parsed.scheme}'. Sadece http/https."

    if not parsed.hostname:
        return False, "Hostname bulunamadı"

    hostname = parsed.hostname.lower()

    # Reject IP literals — then check if private/loopback/link-local
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, f"Private/rezerve IP adresi reddedildi: {hostname}"
        # Also block IPv4-mapped IPv6
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            mapped = ip.ipv4_mapped
            if mapped.is_private or mapped.is_loopback or mapped.is_link_local:
                return False, f"Private IPv4-mapped IPv6 reddedildi: {hostname}"
    except ValueError:
        # Not an IP — it's a domain name, continue to domain check
        pass

    # Block cloud metadata endpoints
    if hostname in ("169.254.169.254", "metadata.google.internal",
                     "metadata.aws.internal", "169.254.170.2"):
        return False, f"Bulut metadata endpoint'i reddedildi: {hostname}"

    # Domain allowlist
    if not _ALLOWED_URL_DOMAINS.match(hostname):
        return False, f"Domain allowlist dışı: '{hostname}'. İzin verilen platformlar: YouTube, Vimeo, TikTok, Instagram, X/Twitter, Facebook, Pexels, Pixabay, Unsplash, Archive.org, Wikimedia, SoundCloud, Bilibili vb."

    return True, "OK"


# ---------------------------------------------------------------------------
# FFmpeg filter value sanitization — filter injection defense
# ---------------------------------------------------------------------------

# Allow only safe characters in font names, ASS color codes, and style values
_SAFE_FONT_RE = re.compile(r"^[A-Za-z0-9 _.-]+$")
_SAFE_ASS_COLOR_RE = re.compile(r"^&H[0-9A-Fa-f]{8}$")
_SAFE_NUMERIC_RE = re.compile(r"^-?\d+(\.\d+)?$")


def sanitize_filter_value(value: Any, max_len: int = 200) -> str:
    """Sanitize a value destined for an FFmpeg filter string.

    Escapes single quotes and rejects values containing newlines or
    other control characters that could break out of the filter context.
    """
    if value is None:
        return ""
    s = str(value)
    # Reject control characters (including newlines, null bytes)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s):
        raise ValueError(f"Filter değeri kontrol karakterleri içeriyor: {s!r}")
    if len(s) > max_len:
        raise ValueError(f"Filter değeri çok uzun ({len(s)} > {max_len}): {s[:50]}...")
    # Escape single quotes by doubling them (FFmpeg filter escaping)
    return s.replace("'", "\\'")


def validate_subtitle_style(style: dict) -> dict:
    """Validate and clamp subtitle style values before building ASS force_style.

    Returns a sanitized copy. Raises ValueError on malicious input.
    """
    cleaned: dict[str, Any] = {}

    font = str(style.get("font", "Inter"))
    if not _SAFE_FONT_RE.match(font):
        raise ValueError(f"Güvensiz font adı: {font!r}")
    cleaned["font"] = font

    def _clamp_int(key: str, default: int, lo: int, hi: int) -> int:
        val = style.get(key, default)
        try:
            ival = int(val)
        except (ValueError, TypeError):
            ival = default
        return max(lo, min(hi, ival))

    cleaned["font_size"] = _clamp_int("font_size", 28, 4, 200)
    cleaned["bold"] = bool(style.get("bold", True))
    cleaned["outline_width"] = _clamp_int("outline_width", 2, 0, 20)
    cleaned["shadow"] = _clamp_int("shadow", 0, 0, 20)
    cleaned["margin_v"] = _clamp_int("margin_v", 40, 0, 500)
    cleaned["alignment"] = _clamp_int("alignment", 2, 1, 9)
    cleaned["border_style"] = _clamp_int("border_style", 1, 1, 4)

    for color_key in ("primary_color", "outline_color", "back_color"):
        cv = style.get(color_key)
        if cv is not None:
            cv_str = str(cv)
            if not _SAFE_ASS_COLOR_RE.match(cv_str):
                raise ValueError(f"Güvensiz ASS renk değeri ({color_key}): {cv_str!r}")
            cleaned[color_key] = cv_str

    return cleaned


# ---------------------------------------------------------------------------
# Path traversal defense — workspace confinement
# ---------------------------------------------------------------------------

def safe_output_path(
    user_path: str | Path,
    default: str | Path,
    workspace_root: str | Path = "projects",
) -> Path:
    """Resolve a user/agent-supplied output path and confine it to workspace_root.

    If the resolved path escapes workspace_root, falls back to `default`
    inside workspace_root. This prevents path traversal (../../etc/passwd).
    """
    workspace = Path(workspace_root).resolve()

    try:
        candidate = Path(user_path).expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        candidate = candidate.resolve()

        # Check if the resolved path is within workspace
        try:
            candidate.relative_to(workspace)
            return candidate
        except ValueError:
            # Path escapes workspace — fall through to default
            pass
    except (OSError, RuntimeError):
        pass

    # Fall back to default within workspace
    default_resolved = Path(default)
    if not default_resolved.is_absolute():
        default_resolved = workspace / default_resolved
    return default_resolved.resolve()
