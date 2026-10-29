"""One layout for every email, laid out like the mail of the big job portals.

A white bar with the logo and a link to the console, a tinted band with what kind of message it is, a centred heading
and one sentence, a white card overlapping the band's lower edge (a password, a grid of alert cards), the rest of the
content, one round button, and a footer. Tables and inline styles only, which is what Gmail, Outlook and Apple Mail
all draw the same, 600 pixels wide and readable on a phone.

The logo and icons are PNGs served by the frontend (``frontend/public/email``), named from ``APP_BASE_URL``. The icons
are Lucide glyphs (ISC licence) drawn on circles.

Everything passed in as text is escaped here; arguments named ``*_html`` are already HTML.
"""

from __future__ import annotations

from html import escape

from app.config import get_settings

APP = "SentinelForge IR"
TINT = "#f1edfd"
ACCENT = "#6d28d9"
FONT = "'Segoe UI',Roboto,Helvetica,Arial,sans-serif"

FRAME = """\
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>{title}</title></head>
<body style="margin:0;padding:0;background:#eef0f4;font-family:{font};color:#101828;-webkit-text-size-adjust:100%;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#eef0f4;">{preview}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f4;padding:24px 8px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;">
        <tr><td style="padding:14px 24px;border-bottom:1px solid #eef0f3;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
            <td style="width:34px;padding-right:10px;vertical-align:middle;"><img src="{base}/email/logo.png" width="30" height="30" alt="" style="display:block;border-radius:7px;"></td>
            <td style="vertical-align:middle;font-size:17px;font-weight:700;color:#1e1b4b;letter-spacing:-.2px;">{app}</td>
            <td align="right" style="vertical-align:middle;font-size:12.5px;"><a href="{base}/dashboard" style="color:#475467;text-decoration:none;">Open console &rsaquo;</a></td>
          </tr></table>
        </td></tr>
        <tr><td align="center" style="background:{tint};padding:30px 32px {hero_bottom};">
          <div style="font:700 11px {font};letter-spacing:1.4px;text-transform:uppercase;color:{accent};">{kind}</div>
          <div style="margin-top:8px;font-size:22px;line-height:1.3;font-weight:700;color:#101828;letter-spacing:-.3px;">{heading}</div>
          <p style="margin:8px auto 0;max-width:440px;font-size:14.5px;line-height:1.55;color:#344054;">{lead}</p>
        </td></tr>
        {top}
        <tr><td style="padding:4px 32px 0;">{body}</td></tr>
        <tr><td align="center" style="padding:24px 32px 30px;">{button}</td></tr>
        <tr><td style="padding:20px 32px 26px;background:#f7f8fa;border-top:1px solid #eef0f3;">
          <p style="margin:0;font-size:12.5px;line-height:1.6;color:#667085;text-align:center;">{footer}</p>
          <p style="margin:10px 0 0;font-size:12px;line-height:1.6;color:#98a2b3;text-align:center;">{app} &middot; Incident response &middot; <a href="{base}" style="color:#98a2b3;">{host}</a><br>This is an automated message. We never ask for your password by email or phone.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""

# The white card overlapping the band: the band's colour runs down behind its first part.
TOP = """<tr><td style="padding:0 32px;background-color:#ffffff;background-image:linear-gradient(to bottom,{tint} 0,{tint} 56px,#ffffff 56px);">{content}</td></tr>"""

CARD = """\
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e4e7ec;border-radius:12px;border-collapse:separate;">
            <tr><td align="{align}" style="padding:{padding};">{content}</td></tr>
          </table>"""

GRID_CELL = """\
<td width="50%" valign="top" style="padding:6px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e4e7ec;border-radius:12px;border-collapse:separate;">
                <tr><td align="center" style="padding:16px 10px 12px;">
                  {icon}
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td height="58" align="center" valign="top" style="padding-top:10px;">
                    <div style="font-size:13.5px;line-height:1.35;font-weight:600;color:#101828;">{label}</div>
                    <div style="margin-top:3px;font-size:12px;line-height:1.4;color:#667085;">{note}</div>
                  </td></tr></table>
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:8px;"><tr>
                    <td align="center" style="background:{tint};border-radius:999px;"><a href="{link}" style="display:block;padding:7px 8px;font-size:12px;font-weight:700;color:{accent};text-decoration:none;">{action}</a></td>
                  </tr></table>
                </td></tr>
              </table>
            </td>"""


def base_url() -> str:
    return get_settings().app_base_url.rstrip("/")


def icon(name: str, size: int = 44) -> str:
    return f'<img src="{escape(base_url())}/email/{name}.png" width="{size}" height="{size}" alt="" style="display:block;margin:0 auto;border:0;">'


def card(content_html: str, padding: str = "20px 24px 22px", align: str = "center") -> str:
    return CARD.format(content=content_html, padding=padding, align=align)


def button(label: str, link: str) -> str:
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;"><tr>'
        f'<td style="background:{ACCENT};border-radius:999px;"><a href="{escape(link, quote=True)}" '
        f'style="display:inline-block;padding:12px 30px;font-size:14.5px;font-weight:700;color:#ffffff;text-decoration:none;">{escape(label)}</a></td>'
        "</tr></table>"
    )


def section_title(title: str) -> str:
    return f'<div style="margin:24px 0 8px;font:600 11.5px {FONT};letter-spacing:1.2px;text-transform:uppercase;color:#667085;">{escape(title)}</div>'


def details(rows: list[tuple[str, str]]) -> str:
    """Label and value rows in a bordered box."""
    cells = "".join(
        f'<tr><td style="padding:10px 16px;{"" if i == 0 else "border-top:1px solid #eaecf0;"}width:38%;font-size:12.5px;color:#667085;vertical-align:top;">{escape(k)}</td>'
        f'<td style="padding:10px 16px 10px 0;{"" if i == 0 else "border-top:1px solid #eaecf0;"}font-size:13.5px;line-height:1.5;color:#101828;">{escape(v)}</td></tr>'
        for i, (k, v) in enumerate(rows)
    )
    return f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e4e7ec;border-radius:12px;border-collapse:separate;">{cells}</table>'


def grid(cards: list[tuple[str, str, str, str, str]]) -> str:
    """Cards two to a row: (icon, name, the line under it, link, what its button says)."""
    cells = [
        GRID_CELL.format(icon=icon(name), label=escape(label), note=escape(note), link=escape(link, quote=True), action=escape(action), tint=TINT, accent=ACCENT)
        for name, label, note, link, action in cards
    ]
    if len(cells) % 2:
        cells.append('<td width="50%" style="padding:6px;"></td>')
    rows = "".join(f"<tr>{cells[i]}{cells[i + 1]}</tr>" for i in range(0, len(cells), 2))
    return f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{rows}</table>'


def page(*, title: str, kind: str, heading: str, lead: str, footer: str, top_html: str = "", body_html: str = "", button_html: str = "", preview: str = "") -> str:
    base = base_url()
    return FRAME.format(
        title=escape(title),
        preview=escape(preview or lead),
        font=FONT,
        tint=TINT,
        accent=ACCENT,
        app=APP,
        base=escape(base, quote=True),
        host=escape(base.split("://", 1)[-1]),
        kind=escape(kind),
        heading=escape(heading),
        lead=escape(lead),
        hero_bottom="64px" if top_html else "30px",
        top=TOP.format(tint=TINT, content=top_html) if top_html else "",
        body=body_html,
        button=button_html,
        footer=escape(footer),
    )
