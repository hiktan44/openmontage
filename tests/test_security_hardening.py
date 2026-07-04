"""Security tests for the hardening patches applied to OpenMontage.

Tests cover:
1. SSRF defense in video_downloader URL validation
2. FFmpeg filter injection defense in subtitle style/path handling
3. Path traversal defense in workspace confinement
4. Backlot project_id strict allowlist
"""

import pytest
from pathlib import Path


class TestSSRFDefense:
    """validate_download_url — blocks private IPs, metadata endpoints, non-allowlisted domains."""

    def test_valid_youtube_url_accepted(self):
        from lib.security import validate_download_url
        ok, _ = validate_download_url("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert ok is True

    def test_valid_vimeo_url_accepted(self):
        from lib.security import validate_download_url
        ok, _ = validate_download_url("https://vimeo.com/123456789")
        assert ok is True

    def test_local_ip_rejected(self):
        from lib.security import validate_download_url
        ok, reason = validate_download_url("http://127.0.0.1:8080/secret")
        assert ok is False
        assert "private" in reason.lower() or "reddedildi" in reason.lower()

    def test_private_network_rejected(self):
        from lib.security import validate_download_url
        ok, reason = validate_download_url("http://192.168.1.1/admin")
        assert ok is False

    def test_cloud_metadata_rejected(self):
        from lib.security import validate_download_url
        ok, reason = validate_download_url("http://169.254.169.254/latest/meta-data/")
        assert ok is False

    def test_aws_metadata_rejected(self):
        from lib.security import validate_download_url
        ok, _ = validate_download_url("http://169.254.170.2/latest/meta-data/")
        assert ok is False

    def test_non_allowlisted_domain_rejected(self):
        from lib.security import validate_download_url
        ok, reason = validate_download_url("https://evil.example.com/steal")
        assert ok is False
        assert "allowlist" in reason.lower() or "domain" in reason.lower()

    def test_non_http_scheme_rejected(self):
        from lib.security import validate_download_url
        ok, reason = validate_download_url("file:///etc/passwd")
        assert ok is False
        assert "şema" in reason.lower() or "scheme" in reason.lower()

    def test_empty_url_rejected(self):
        from lib.security import validate_download_url
        ok, _ = validate_download_url("")
        assert ok is False

    def test_none_url_rejected(self):
        from lib.security import validate_download_url
        ok, _ = validate_download_url(None)  # type: ignore
        assert ok is False

    def test_archivedotorg_accepted(self):
        from lib.security import validate_download_url
        ok, _ = validate_download_url("https://archive.org/details/somevideo")
        assert ok is True


class TestFFmpegFilterSanitization:
    """sanitize_filter_value — blocks control chars, newlines, quote injection."""

    def test_normal_string_passes(self):
        from lib.security import sanitize_filter_value
        result = sanitize_filter_value("/tmp/video/output.mp4")
        assert "output.mp4" in result

    def test_single_quote_escaped(self):
        from lib.security import sanitize_filter_value
        result = sanitize_filter_value("hello'world")
        assert "\\'" in result

    def test_newline_rejected(self):
        from lib.security import sanitize_filter_value
        with pytest.raises(ValueError, match="kontrol karakter"):
            sanitize_filter_value("safe\nmalicious")

    def test_null_byte_rejected(self):
        from lib.security import sanitize_filter_value
        with pytest.raises(ValueError, match="kontrol karakter"):
            sanitize_filter_value("safe\x00evil")

    def test_carriage_return_rejected(self):
        from lib.security import sanitize_filter_value
        with pytest.raises(ValueError):
            sanitize_filter_value("safe\rmalicious")

    def test_oversized_value_rejected(self):
        from lib.security import sanitize_filter_value
        with pytest.raises(ValueError, match="çok uzun"):
            sanitize_filter_value("A" * 300)

    def test_none_returns_empty(self):
        from lib.security import sanitize_filter_value
        assert sanitize_filter_value(None) == ""


class TestSubtitleStyleValidation:
    """validate_subtitle_style — clamps numerics, validates font/color."""

    def test_valid_style_passes(self):
        from lib.security import validate_subtitle_style
        result = validate_subtitle_style({
            "font": "Arial",
            "font_size": 28,
            "bold": True,
            "primary_color": "&H00FFFFFF",
            "outline_color": "&H00000000",
        })
        assert result["font"] == "Arial"
        assert result["font_size"] == 28

    def test_malicious_font_rejected(self):
        from lib.security import validate_subtitle_style
        with pytest.raises(ValueError, match="font"):
            validate_subtitle_style({"font": "Arial';evil=f"})

    def test_font_with_special_chars_rejected(self):
        from lib.security import validate_subtitle_style
        with pytest.raises(ValueError):
            validate_subtitle_style({"font": "font;rm -rf"})

    def test_font_size_clamped_low(self):
        from lib.security import validate_subtitle_style
        result = validate_subtitle_style({"font_size": -100})
        assert result["font_size"] == 4  # clamped to minimum

    def test_font_size_clamped_high(self):
        from lib.security import validate_subtitle_style
        result = validate_subtitle_style({"font_size": 99999})
        assert result["font_size"] == 200  # clamped to maximum

    def test_font_size_non_numeric_uses_default(self):
        from lib.security import validate_subtitle_style
        result = validate_subtitle_style({"font_size": "not a number"})
        assert result["font_size"] == 28

    def test_invalid_color_rejected(self):
        from lib.security import validate_subtitle_style
        with pytest.raises(ValueError, match="renk"):
            validate_subtitle_style({"primary_color": "'; rm -rf /"})

    def test_invalid_color_format_rejected(self):
        from lib.security import validate_subtitle_style
        with pytest.raises(ValueError):
            validate_subtitle_style({"primary_color": "#FFFFFF"})

    def test_margin_v_clamped(self):
        from lib.security import validate_subtitle_style
        result = validate_subtitle_style({"margin_v": 99999})
        assert result["margin_v"] == 500

    def test_default_values_when_empty(self):
        from lib.security import validate_subtitle_style
        result = validate_subtitle_style({})
        assert result["font"] == "Inter"
        assert result["font_size"] == 28


class TestPathTraversalDefense:
    """safe_output_path — confines output to workspace root."""

    def test_normal_relative_path(self, tmp_path):
        from lib.security import safe_output_path
        result = safe_output_path("myvideo.mp4", "default.mp4", workspace_root=str(tmp_path))
        assert str(result) == str(tmp_path / "myvideo.mp4")

    def test_traversal_blocked(self, tmp_path):
        from lib.security import safe_output_path
        result = safe_output_path("../../etc/passwd", "default.mp4", workspace_root=str(tmp_path))
        # Should fall back to default, NOT /etc/passwd
        assert str(tmp_path) in str(result)
        assert "passwd" not in str(result)

    def test_absolute_path_outside_workspace_blocked(self, tmp_path):
        from lib.security import safe_output_path
        result = safe_output_path("/etc/passwd", "default.mp4", workspace_root=str(tmp_path))
        assert str(tmp_path) in str(result)
        assert "passwd" not in str(result)

    def test_absolute_path_inside_workspace_allowed(self, tmp_path):
        from lib.security import safe_output_path
        result = safe_output_path(str(tmp_path / "nested" / "video.mp4"),
                                   "default.mp4", workspace_root=str(tmp_path))
        assert str(tmp_path) in str(result)


class TestBacklotProjectId:
    """_safe_project_dir — strict [A-Za-z0-9_-] allowlist."""

    def test_valid_project_id(self):
        from backlot.server import _safe_project_dir
        # This may raise 404 if the project doesn't exist, but should NOT raise 400
        try:
            _safe_project_dir("my-project_123")
        except Exception as e:
            # 404 is OK (project doesn't exist), 400 is NOT OK
            assert "404" in str(e) or "unknown project" in str(e).lower()

    def test_traversal_rejected(self):
        from backlot.server import _safe_project_dir
        with pytest.raises(Exception) as exc_info:
            _safe_project_dir("../../etc/passwd")
        assert "400" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()

    def test_dot_rejected(self):
        from backlot.server import _safe_project_dir
        with pytest.raises(Exception) as exc_info:
            _safe_project_dir(".")
        assert "400" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()

    def test_dotdot_rejected(self):
        from backlot.server import _safe_project_dir
        with pytest.raises(Exception) as exc_info:
            _safe_project_dir("..")
        assert "400" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()

    def test_special_chars_rejected(self):
        from backlot.server import _safe_project_dir
        with pytest.raises(Exception) as exc_info:
            _safe_project_dir("my project!")  # space and ! not allowed
        assert "400" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()

    def test_colon_rejected(self):
        from backlot.server import _safe_project_dir
        with pytest.raises(Exception) as exc_info:
            _safe_project_dir("C:evil")
        assert "400" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()
