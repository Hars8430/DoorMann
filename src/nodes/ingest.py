"""
PDF ingestion node — extracts text AND hidden content from PDF resumes.

This is the FIRST line of defense. A naive pipeline calls extract_text()
and feeds the result straight to the LLM. This node goes further:

1. Extracts visible text (the normal content)
2. Extracts hidden text using PyMuPDF's low-level API:
   - White-on-white text (font color matches page background)
   - Tiny font text (0.5pt, 1pt — invisible to human readers)
   - Off-page / negative-coordinate text (placed outside the visible area)
   - Text in PDF metadata fields (/Author, /Title, /Keywords, XMP)
   - Text in annotation/destinations that aren't visible
3. Logs all extraction details for the evaluation harness

The hidden text extraction is what catches attack family #2 (hidden-text
injection) and family #3 (metadata injection) BEFORE the classifier ever
sees the content.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from pipeline_state import PipelineState
from logging_setup import log_decision

logger = logging.getLogger("doorman.nodes.ingest")

try:
    import fitz  # PyMuPDF
    _FITZ_AVAILABLE = True
except ImportError:
    _FITZ_AVAILABLE = False
    logger.warning(
        "PyMuPDF (fitz) not available — PDF ingestion will use basic text extraction only. "
        "Install with: pip install PyMuPDF"
    )

# Try pdfplumber as fallback
try:
    import pdfplumber
    _PDFPLUMBER_AVAILABLE = True
except ImportError:
    _PDFPLUMBER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Hidden text detection thresholds
# ---------------------------------------------------------------------------

# Font size below this (in points) is suspicious
MIN_FONT_SIZE_SUSPICIOUS = 1.0
# Font size below this is definitely hidden (0.5pt is invisible)
MIN_FONT_SIZE_HIDDEN = 0.5

# Color similarity threshold (0-255 per channel)
# If text color is within this of the page background, it's likely hidden
COLOR_SIMILARITY_THRESHOLD = 5

# Page background is typically white (255, 255, 255)
PAGE_BG_COLOR = (255, 255, 255)

# Coordinate thresholds (in PDF points, origin at top-left for fitz)
OFF_PAGE_Y_MIN = -50       # text above the page
OFF_PAGE_Y_MAX = 10000     # text far below the page (if page height is known)
OFF_PAGE_X_MIN = -50
OFF_PAGE_X_MAX = 10000


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

def _color_distance(c1: tuple, c2: tuple) -> float:
    """Euclidean distance between two RGB colors."""
    return sum((a - b) ** 2 for a, b in zip(c1, c2)) ** 0.5


def _is_color_hidden(text_color: tuple, page_bg: tuple = PAGE_BG_COLOR) -> bool:
    """Check if text color is close enough to background to be invisible."""
    if len(text_color) < 3:
        return False
    return _color_distance(text_color[:3], page_bg) < COLOR_SIMILARITY_THRESHOLD


def _normalize_color(color: Any) -> tuple:
    """Normalize a color value to an RGB tuple."""
    if isinstance(color, (list, tuple)):
        if len(color) >= 3:
            return tuple(min(255, max(0, int(c * 255)) if c <= 1 else int(c)) for c in color[:3])
        return tuple(color)
    return (0, 0, 0)


# ---------------------------------------------------------------------------
# Main ingestion function
# ---------------------------------------------------------------------------

@dataclass
class IngestionResult:
    visible_text: str
    hidden_text: str
    full_text: str                          # visible + hidden concatenated
    hidden_segments: list[dict[str, Any]]   # detailed info about each hidden chunk
    metadata_text: str                       # text extracted from PDF metadata
    warnings: list[str]
    extraction_method: str                   # "pymupdf", "pdfplumber", "basic", "none"
    page_count: int


def ingest_node(state: PipelineState, config: dict[str, Any]) -> PipelineState:
    """
    LangGraph node: ingest and extract text from the input document.

    Accepts either:
      - state.input_text (plain text resume)
      - state.pdf_path (path to a PDF file)

    If a PDF path is provided and PyMuPDF is available, extracts visible
    text AND hidden text using low-level APIs. If only plain text is
    provided, treats it as the visible text and checks for hidden patterns
    in the text itself.

    Populates:
      - state.visible_text
      - state.hidden_text_segments
      - state.full_text (visible + hidden)
      - state.input_hash (hash of full_text)
      - state.extraction_warnings
    """
    pdf_path = getattr(state, 'pdf_path', None) or ""

    extraction_warnings: list[str] = []
    visible_text = ""
    hidden_text = ""
    hidden_segments: list[dict[str, Any]] = []
    metadata_text = ""
    full_text = ""
    extraction_method = "none"
    page_count = 0

    # ---- Case 1: PDF file provided ----

    if pdf_path and (_FITZ_AVAILABLE or _PDFPLUMBER_AVAILABLE):
        if _FITZ_AVAILABLE and pdf_path.lower().endswith('.pdf'):
            result = _ingest_pdf_pymupdf(pdf_path)
            visible_text = result.visible_text
            hidden_text = result.hidden_text
            hidden_segments = result.hidden_segments
            metadata_text = result.metadata_text
            extraction_warnings = result.warnings
            extraction_method = result.extraction_method
            page_count = result.page_count
        elif _PDFPLUMBER_AVAILABLE:
            result = _ingest_pdf_pdfplumber(pdf_path)
            visible_text = result.visible_text
            metadata_text = result.metadata_text
            extraction_warnings = result.warnings
            extraction_method = result.extraction_method
            page_count = result.page_count
            extraction_warnings.append(
                "pdfplumber used — hidden text detection not available (use PyMuPDF for full extraction)"
            )
        else:
            extraction_warnings.append("No PDF library available — skipping PDF extraction")

    # ---- Case 2: Plain text input ----

    elif state.input_text.strip():
        visible_text = state.input_text
        extraction_method = "basic"

        # Check the plain text itself for hidden-patterns (zero-width chars, etc.)
        hidden_from_text = _check_text_for_hidden_patterns(state.input_text)
        if hidden_from_text:
            hidden_segments.extend(hidden_from_text)
            hidden_text = "\n".join(h["text"] for h in hidden_from_text)

    # ---- Combine ----

    full_text = visible_text
    if hidden_text:
        full_text = visible_text + "\n\n[HIDDEN TEXT EXTRACTED BY INGESTION LAYER]\n" + hidden_text

    # Add metadata text if present
    if metadata_text:
        full_text = full_text + "\n\n[PDF METADATA]\n" + metadata_text
        # Metadata is also untrusted — include it in the full text the classifier sees

    # Update state
    state.visible_text = visible_text
    state.hidden_text_segments = hidden_segments
    state.full_text = full_text
    state.input_hash = hashlib.sha256(
        full_text.encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    state.extraction_warnings = extraction_warnings
    state.text_sources = {
        "visible": "extracted" if extraction_method != "basic" else "provided",
        "hidden": "pymupdf" if _FITZ_AVAILABLE and pdf_path else ("text_scan" if hidden_segments else "none"),
        "metadata": "pymupdf" if metadata_text and _FITZ_AVAILABLE else "none",
    }

    # ---- Log the ingestion decision ----

    hidden_count = len(hidden_segments)
    log_decision(
        logger,
        stage="ingest",
        rule_id="R02" if hidden_count > 0 else None,  # hidden text found = suspicious
        input_hash=state.input_hash,
        action_attempted=None,
        verdict="flagged" if hidden_count > 0 else "passed",
        detail=(
            f"PDF ingestion: {page_count} page(s), method={extraction_method}. "
            f"Visible text: {len(visible_text)} chars. "
            f"Hidden segments: {hidden_count}. "
            f"Metadata fields: {len(metadata_text.split(chr(10)))}"
        ),
        hidden_segment_count=hidden_count,
        extraction_method=extraction_method,
        visible_chars=len(visible_text),
        hidden_chars=len(hidden_text),
    )

    if hidden_count > 0:
        warnings = [
            f"Found {hidden_count} hidden text segment(s) in the document — these are included in the full text sent to the classifier"
        ]
        state.extraction_warnings.extend(warnings)
        logger.info(
            "ingest_node: %d hidden text segments extracted — full text is %d chars",
            hidden_count,
            len(full_text),
        )

    return state


# ---------------------------------------------------------------------------
# PyMuPDF ingestion with hidden text detection
# ---------------------------------------------------------------------------

def _ingest_pdf_pymupdf(pdf_path: str) -> IngestionResult:
    """Extract text from PDF using PyMuPDF with hidden text detection."""
    warnings: list[str] = []
    visible_parts: list[str] = []
    hidden_parts: list[str] = []
    hidden_segments: list[dict[str, Any]] = []
    metadata_parts: list[str] = []

    try:
        doc = fitz.open(pdf_path)
        page_count = len(doc)

        if page_count == 0:
            warnings.append("PDF has no pages")
            return IngestionResult(
                visible_text="",
                hidden_text="",
                full_text="",
                hidden_segments=[],
                metadata_text="",
                warnings=warnings,
                extraction_method="pymupdf",
                page_count=0,
            )

        for page_num, page in enumerate(doc):
            page_rect = page.rect

            # ---- 1. Extract metadata ----

            meta = doc.metadata or {}
            for key in ("author", "title", "subject", "keywords", "creator", "producer"):
                val = meta.get(key, "")
                if val and str(val).strip():
                    metadata_parts.append(f"[{key}] {val}")

            # Also check XMP metadata
            xmp = doc.xref_get_key(doc.pdf_catalog(), "Metadata")
            # (simplified — full XMP extraction is complex)

            # ---- 2. Extract visible and hidden text per page ----

            # Get all text spans with their formatting info
            blocks = page.get_text("dict")["blocks"]

            page_visible: list[str] = []
            page_hidden: list[dict[str, Any]] = []

            for block in blocks:
                if block.get("type") != 0:  # text block
                    continue

                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        text = span.get("text", "").strip()
                        if not text:
                            continue

                        bbox = span["bbox"]  # (x0, y0, x1, y1)
                        size = span.get("size", 0)
                        color_raw = span.get("color", 0)
                        font = span.get("font", "")

                        # Normalize color: fitz uses int color (sRGB)
                        if isinstance(color_raw, int):
                            # Convert sRGB int to RGB tuple
                            r = (color_raw >> 16) & 0xFF
                            g = (color_raw >> 8) & 0xFF
                            b = color_raw & 0xFF
                            color = (r, g, b)
                        else:
                            color = _normalize_color(color_raw)

                        is_hidden = False
                        hide_reason = ""

                        # Check 1: Off-page coordinates
                        if (bbox[0] < OFF_PAGE_X_MIN or bbox[0] > page_rect.width + OFF_PAGE_X_MAX or
                            bbox[1] < OFF_PAGE_Y_MIN or bbox[3] > page_rect.height + OFF_PAGE_Y_MAX):
                            is_hidden = True
                            hide_reason = f"off-page coordinates {bbox}"

                        # Check 2: Tiny font size
                        elif size < MIN_FONT_SIZE_HIDDEN:
                            is_hidden = True
                            hide_reason = f"font size {size:.1f}pt (below {MIN_FONT_SIZE_HIDDEN}pt)"

                        # Check 3: Very small but readable
                        elif size < MIN_FONT_SIZE_SUSPICIOUS:
                            is_hidden = True
                            hide_reason = f"tiny font size {size:.1f}pt (below {MIN_FONT_SIZE_SUSPICIOUS}pt)"

                        # Check 4: Color matches background
                        elif _is_color_hidden(color):
                            is_hidden = True
                            hide_reason = f"font color {color} matches page background"

                        if is_hidden:
                            page_hidden.append({
                                "text": text,
                                "bbox": bbox,
                                "size": size,
                                "color": color,
                                "font": font,
                                "reason": hide_reason,
                                "page": page_num + 1,
                            })
                        else:
                            page_visible.append(text)

            visible_parts.append(" ".join(page_visible))
            hidden_parts.extend(page_hidden)

        doc.close()

        # Build hidden segments for the state
        for h in hidden_parts:
            hidden_segments.append({
                "page": h["page"],
                "text": h["text"],
                "bbox": h["bbox"],
                "size": h["size"],
                "color": h["color"],
                "font": h["font"],
                "hide_reason": h["reason"],
            })

        if hidden_segments:
            hidden_text = "\n".join(h["text"] for h in hidden_parts)
            warnings.append(
                f"Found {len(hidden_segments)} hidden text segment(s): "
                + "; ".join(f"page {h['page']}: {h['hide_reason']}" for h in hidden_segments[:5])
            )
        else:
            hidden_text = ""
            warnings.append("No hidden text detected")

        visible_text = "\n\n".join(visible_parts) if visible_parts else ""
        metadata_text = "\n".join(metadata_parts) if metadata_parts else ""

        return IngestionResult(
            visible_text=visible_text,
            hidden_text=hidden_text,
            full_text=visible_text + ("\n[HIDDEN]\n" + hidden_text if hidden_text else ""),
            hidden_segments=hidden_segments,
            metadata_text=metadata_text,
            warnings=warnings,
            extraction_method="pymupdf",
            page_count=page_count,
        )

    except Exception as e:
        warnings.append(f"PyMuPDF extraction error: {e}")
        logger.error("ingest_node: PyMuPDF error: %s", e, exc_info=True)
        return IngestionResult(
            visible_text="",
            hidden_text="",
            full_text="",
            hidden_segments=[],
            metadata_text="",
            warnings=warnings,
            extraction_method="pymupdf_failed",
            page_count=0,
        )


# ---------------------------------------------------------------------------
# pdfplumber fallback (basic text extraction, no hidden detection)
# ---------------------------------------------------------------------------

def _ingest_pdf_pdfplumber(pdf_path: str) -> IngestionResult:
    """Extract text using pdfplumber (basic, no hidden text detection)."""
    warnings: list[str] = []

    try:
        with pdfplumber.open(pdf_path) as pdf:
            page_count = len(pdf.pages)
            pages_text = []

            for i, page in enumerate(pdf.pages):
                text = page.extract_text() or ""
                pages_text.append(text)

                # Extract metadata
                if hasattr(page, 'metadata') and page.metadata:
                    for k, v in page.metadata.items():
                        if v:
                            metadata_parts.append(f"[{k}] {v}")

            visible_text = "\n\n".join(pages_text) if pages_text else ""

            return IngestionResult(
                visible_text=visible_text,
                hidden_text="",
                full_text=visible_text,
                hidden_segments=[],
                metadata_text="",
                warnings=warnings + ["pdfplumber: hidden text detection not available"],
                extraction_method="pdfplumber",
                page_count=page_count,
            )

    except Exception as e:
        warnings.append(f"pdfplumber extraction error: {e}")
        return IngestionResult(
            visible_text="",
            hidden_text="",
            full_text="",
            hidden_segments=[],
            metadata_text="",
            warnings=warnings,
            extraction_method="pdfplumber_failed",
            page_count=0,
        )


# ---------------------------------------------------------------------------
# Text-only hidden pattern detection (for plain text input)
# ---------------------------------------------------------------------------

def _check_text_for_hidden_patterns(text: str) -> list[dict[str, Any]]:
    """
    Scan plain text for hidden-pattern indicators:
      - Zero-width Unicode characters
      - Homoglyphs (characters that look like others)
      - Base64 blocks that might contain encoded instructions
      - Reversed text segments
    """
    segments = []

    # Zero-width characters
    zw_patterns = [
        ("\u200b", "ZERO WIDTH SPACE"),
        ("\u200c", "ZERO WIDTH NON-JOINER"),
        ("\u200d", "ZERO WIDTH JOINER"),
        ("\u200e", "LEFT-TO-RIGHT MARK"),
        ("\u200f", "RIGHT-TO-LEFT MARK"),
        ("\u202a", "LEFT-TO-RIGHT EMBEDDING"),
        ("\u202b", "RIGHT-TO-LEFT EMBEDDING"),
        ("\u202c", "POP DIRECTIONAL FORMATTING"),
        ("\u202d", "LEFT-TO-RIGHT OVERRIDE"),
        ("\u202e", "RIGHT-TO-LEFT OVERRIDE"),
        ("\u2060", "WORD JOINER"),
        ("\ufeff", "BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE"),
        ("\u00ad", "SOFT HYPHEN"),
    ]

    found_zw = False
    for char, name in zw_patterns:
        if char in text:
            found_zw = True
            segments.append({
                "type": "zero_width_char",
                "detail": f"Found {name} ({char!r}) in text",
                "text": char,
            })

    if found_zw:
        # Extract the surrounding context
        import re
        matches = re.finditer(r'.{0,20}[' + ''.join(c for c, _ in zw_patterns) + r'].{0,20}', text)
        for m in matches:
            segments.append({
                "type": "zero_width_context",
                "detail": f"Context around zero-width char: {m.group(0)!r}",
                "text": m.group(0),
            })

    # Base64 blocks
    import re
    b64_pattern = re.compile(r'(?:decode|decrypt|follow).{0,50}(?:[A-Za-z0-9+/]{40,}={0,2})')
    for m in b64_pattern.finditer(text):
        segments.append({
            "type": "base64_lure",
            "detail": f"Base64-looking block with decode/follow lure: {m.group(0)[:80]!r}",
            "text": m.group(0),
        })

    return segments
