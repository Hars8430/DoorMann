"""Ingestion layer.

This is where the attacks actually live. A PDF is not "a string of text" —
it's a layout of positioned, styled glyph runs, plus a metadata dict, plus
optional link annotations. A pipeline that calls PyMuPDF's plain
`page.get_text()` and hands the result straight to an LLM has already lost:
it throws away exactly the signal (color, size, position) that would have
caught the attack.

We walk every text span ourselves and classify it as visible or hidden
*before* anything is concatenated into a prompt.
"""
from __future__ import annotations

import re
import pymupdf as fitz  # PyMuPDF (the `fitz` import name is deprecated upstream)

from .models import Document, HiddenSpan

ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}
_URL_RE = re.compile(r"https?://[^\s)]+")


def _rgb_from_packed(color_int: int) -> tuple[int, int, int]:
    r = (color_int >> 16) & 255
    g = (color_int >> 8) & 255
    b = color_int & 255
    return r, g, b


def _looks_like_background(color_int: int, threshold: int = 12) -> bool:
    """True if the glyph color is within `threshold` of white.

    Real documents are near-universally authored on a white canvas, so
    near-white ink is the tell for "author never intended a human to read
    this." (A production system would sample the actual page background
    instead of assuming white — noted in the README as a known limitation.)
    """
    r, g, b = _rgb_from_packed(color_int)
    return all(c >= 255 - threshold for c in (r, g, b))


def _strip_zero_width(text: str) -> str:
    return "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)


def extract_document(path: str) -> Document:
    doc = fitz.open(path)

    visible_parts: list[str] = []
    hidden_spans: list[HiddenSpan] = []
    obfuscated_runs = 0

    for page_num, page in enumerate(doc):
        rect = page.rect
        raw = page.get_text("dict")

        for block in raw.get("blocks", []):
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text = span.get("text", "")
                    if not text.strip():
                        continue

                    size = span.get("size", 0.0)
                    color = span.get("color", 0)
                    x0, y0, x1, y1 = span.get("bbox", (0, 0, 0, 0))

                    reasons = []
                    if _looks_like_background(color):
                        reasons.append("white_on_white")
                    if size <= 1.5:
                        reasons.append("tiny_font")
                    if x1 < 0 or y1 < 0 or x0 > rect.width or y0 > rect.height:
                        reasons.append("off_page")

                    has_zero_width = any(ch in ZERO_WIDTH_CHARS for ch in text)
                    if has_zero_width:
                        obfuscated_runs += 1

                    if reasons:
                        hidden_spans.append(
                            HiddenSpan(text=text, reason="+".join(reasons), page=page_num)
                        )
                    else:
                        # visible run — still strip zero-width chars so the guard
                        # sees the real words, but keep the run in "visible" text
                        # since a human skimming the PDF would see it too.
                        visible_parts.append(_strip_zero_width(text))

    visible_text = " ".join(visible_parts)

    # metadata: the fields a naive pipeline reads for "candidate name / title"
    # and feeds straight into a prompt without a second thought
    meta = doc.metadata or {}
    metadata_text = {
        k: v
        for k, v in {
            "title": meta.get("title", ""),
            "author": meta.get("author", ""),
            "subject": meta.get("subject", ""),
            "keywords": meta.get("keywords", ""),
            "creator": meta.get("creator", ""),
        }.items()
        if v
    }

    # linked URLs — the tool-result-injection surface. Doorman does not
    # fetch these itself; it hands them to the caller so a "fetch portfolio"
    # tool call can be routed through the same guard on the way back in.
    linked_urls: list[str] = []
    for page in doc:
        for link in page.get_links():
            uri = link.get("uri")
            if uri:
                linked_urls.append(uri)
    linked_urls += _URL_RE.findall(visible_text)
    linked_urls = sorted(set(linked_urls))

    doc.close()

    if obfuscated_runs:
        hidden_spans.append(
            HiddenSpan(
                text=f"<{obfuscated_runs} run(s) contained zero-width characters>",
                reason="zero_width_chars",
                page=-1,
            )
        )

    return Document(
        filename=path.split("/")[-1],
        visible_text=visible_text,
        hidden_spans=hidden_spans,
        metadata_text=metadata_text,
        linked_urls=linked_urls,
    )
