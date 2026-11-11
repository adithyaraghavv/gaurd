"""Judging a response body. Row-level security usually answers a caller who may not see the rows with
`200 []`, not `403`. That is correct behavior, so a status code alone cannot tell a leak from a filter."""
from __future__ import annotations

import json


def is_empty_body(body: str) -> bool:
    """True for no content, or JSON that carries no data: [], {}, null, "", or an object whose values are all
    empty (e.g. {"data": [], "error": null}). Anything that is not JSON, or has any value in it, is content."""
    text = (body or "").strip()
    if not text:
        return True
    try:
        data = json.loads(text)
    except ValueError:
        return False  # an HTML page or plain text is content
    return _empty(data)


def _empty(v) -> bool:
    if v is None or v == "" or v == [] or v == {}:
        return True
    if isinstance(v, dict):
        return all(_empty(x) for x in v.values())
    if isinstance(v, list):
        return all(_empty(x) for x in v)
    return False  # numbers, booleans and non-empty strings are data
