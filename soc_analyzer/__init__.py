"""SOC Log Analyzer — detection engine shared by the CLI and the web app."""

from .engine import VERSION, analyze, analyze_files
from .report import format_text

__all__ = ["VERSION", "analyze", "analyze_files", "format_text"]
