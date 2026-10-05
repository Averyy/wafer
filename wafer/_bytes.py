"""Copy wreq's binary return values into ``bytes``/``str`` at the boundary.

Since wreq 0.13 response bodies, stream chunks and ``HeaderMap`` names and
values are read-only ``memoryview`` objects rather than ``bytes``. A
``memoryview`` has no ``decode()`` and fails ``isinstance(x, bytes)``, so code
written for the old shape either raised or, worse, skipped the chunk or
``str()``-ed it into ``"<memory at 0x...>"`` without any error. Every place
wafer receives binary data from wreq converts it here, once.
"""

_BINARY = (bytes, bytearray, memoryview)


def is_binary(value) -> bool:
    """Whether ``value`` is binary data in any shape wreq has returned."""

    return isinstance(value, _BINARY)


def as_bytes(value) -> bytes:
    """Return ``value`` as immutable ``bytes``; ``str`` is encoded as UTF-8."""

    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"expected binary data, got {type(value).__name__}")


def as_text(value, encoding: str = "utf-8", errors: str = "replace") -> str:
    """Decode binary ``value``; a ``str`` passes through unchanged."""

    if isinstance(value, str):
        return value
    if isinstance(value, _BINARY):
        return bytes(value).decode(encoding, errors=errors)
    return str(value)
