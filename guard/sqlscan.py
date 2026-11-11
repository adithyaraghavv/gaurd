"""A small SQL scanner shared by the static database checks.

It does just enough lexing to avoid the mistakes regexes make on real migration files: comments are dropped,
and `;` only ends a statement when it is outside a string, a quoted identifier and a dollar-quoted body
(function bodies and DO blocks keep their text, so callers can still look inside them)."""
from __future__ import annotations

import re

_DOLLAR = re.compile(r"\$([A-Za-z_]\w*)?\$")


def split_statements(sql: str) -> list[str]:
    """Statements without comments, in file order. Empty statements are dropped."""
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        two = sql[i:i + 2]
        if two == "--":
            j = sql.find("\n", i)
            i = n if j == -1 else j
            buf.append(" ")
            continue
        if two == "/*":  # block comments nest in Postgres
            depth, i = 1, i + 2
            while i < n and depth:
                if sql[i:i + 2] == "/*":
                    depth, i = depth + 1, i + 2
                elif sql[i:i + 2] == "*/":
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            buf.append(" ")
            continue
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if sql[j + 1:j + 2] == c:  # doubled quote is an escaped quote
                        j += 2
                        continue
                    break
                j += 1
            buf.append(sql[i:j + 1])
            i = j + 1
            continue
        if c == "$":
            m = _DOLLAR.match(sql, i)
            if m:
                tag = m.group(0)
                j = sql.find(tag, m.end())
                j = n if j == -1 else j + len(tag)
                buf.append(sql[i:j])
                i = j
                continue
        if c == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def strip_comments(sql: str) -> str:
    return ";\n".join(split_statements(sql))


def ident(raw: str) -> str:
    """`"public"."Notes"` -> `public.notes` (lower-cased, quotes removed)."""
    return raw.replace('"', "").strip().lower()


def bare(raw: str) -> str:
    """The table or function name without its schema: `public.notes` -> `notes`."""
    return ident(raw).rsplit(".", 1)[-1]


def split_top_level(text: str, sep: str = ",") -> list[str]:
    """Split on `sep` outside quotes and brackets (for column lists, VALUES tuples, role lists)."""
    parts, depth, cur, quote = [], 0, [], ""
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if cur or parts:
        parts.append("".join(cur).strip())
    return [p for p in parts if p]
