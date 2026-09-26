"""Render the markdown audit report to PDF (optional dependency: reportlab)."""
from __future__ import annotations

from xml.sax.saxutils import escape


def markdown_to_pdf(md: str, path: str, max_table_rows: int = 400) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table,
                                        TableStyle)
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pip install 'vantage[report]' for PDF export") from e

    ss = getSampleStyleSheet()
    cell = ss["BodyText"].clone("cell", fontSize=7, leading=8.5)
    story, table, code = [], [], None

    def inline(s: str) -> str:
        s = escape(s)
        parts = s.split("**")
        s = "".join(f"<b>{p}</b>" if i % 2 else p for i, p in enumerate(parts))
        parts = s.split("`")
        return "".join(f"<font face='Courier'>{p}</font>" if i % 2 else p for i, p in enumerate(parts))

    def flush_table():
        if not table:
            return
        rows = [r for r in table if not set("".join(r)) <= set("- :")]
        rows = rows[: max_table_rows + 1]
        data = [[Paragraph(inline(c if len(c) < 700 else c[:700] + " ..."), cell) for c in r] for r in rows]
        width = landscape(A4)[0] - 56
        t = Table(data, repeatRows=1, colWidths=[width / len(rows[0])] * len(rows[0]))
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
        story.append(Spacer(1, 6))
        table.clear()

    for line in md.splitlines():
        if line.startswith("```"):
            if code is None:
                flush_table()
                code = []
            else:
                story.append(Preformatted("\n".join(code), ss["Code"].clone("c", fontSize=6.5, leading=8)))
                code = None
            continue
        if code is not None:
            code.append(line)
            continue
        if line.startswith("|"):
            table.append([c.strip() for c in line.strip().strip("|").split("|")])
            continue
        flush_table()
        if line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), ss["Title"]))
        elif line.startswith("## "):
            story.append(Paragraph(inline(line[3:]), ss["Heading2"]))
        elif line.startswith("> "):
            story.append(Paragraph(f"<i>{inline(line[2:])}</i>", ss["BodyText"]))
        elif line.startswith(("- ", "* ")) or line[:3].rstrip(".").isdigit():
            story.append(Paragraph(inline(line), ss["BodyText"], bulletText="•"
                                   if line.startswith(("- ", "* ")) else None))
        elif line.strip():
            story.append(Paragraph(inline(line), ss["BodyText"]))
    flush_table()
    SimpleDocTemplate(path, pagesize=landscape(A4), title="VANTAGE audit report",
                      leftMargin=28, rightMargin=28, topMargin=28, bottomMargin=28).build(story)
