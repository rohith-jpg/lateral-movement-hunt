"""JSON boundary types; known event fields are validated during ingestion."""

from typing import Any, TypeAlias

Event: TypeAlias = dict[str, Any]
Alert: TypeAlias = dict[str, Any]
