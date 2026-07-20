"""Protocol providers. Implementations never serialize target credentials."""

from .registry import provider_for

__all__ = ["provider_for"]
