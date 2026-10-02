"""Deterministic rule-based detection over normalized events."""
from .engine import DetectionEngine, DetectionContext, load_config

__all__ = ["DetectionEngine", "DetectionContext", "load_config"]
