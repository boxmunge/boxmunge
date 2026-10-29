"""The /v1/admin/stats HTML page: daily checks per version, recent failure reports.

Plain server-rendered HTML with inline CSS, no scripts. Every stored string
(failure reports carry client-supplied text) is escaped.
"""

from html import escape

NOTE = ("Counts are /v1/check requests, not unique boxes: one box checks about 4 times "
        "a day. A version marked unlisted is not in releases.json (a dev build or a "
        "dropped release); the version \"unlisted\" collects the overflow beyond the "
        "per-day cap on distinct versions.")

STYLE = """
body{font:14px/1.4 system-ui,sans-serif;margin:1.5rem;color:#222;background:#fff}
table{border-collapse:collapse;margin:.5rem 0 1.5rem}
th,td{border:1px solid #ccc;padding:.25rem .6rem;text-align:right}
th{background:#f3f3f3}td.l,th.l{text-align:left}
.note{max-width:60rem;color:#555}
@media (prefers-color-scheme:dark){body{background:#181818;color:#ddd}
th{background:#262626}th,td{border-color:#444}.note{color:#aaa}}
"""


def _cell(value: object, cls: str = "") -> str:
    return f'<td class="{cls}">{escape(str(value))}</td>' if cls else f"<td>{escape(str(value))}</td>"


def _checks_table(stats: dict) -> str:
    versions = [t["version"] for t in stats["totals"]]
    if not versions:
        return "<p>No checks recorded in this window.</p>"
    listed = {t["version"]: t["listed"] for t in stats["totals"]}
    by_cell = {(r["date"], r["version"]): r["count"] for r in stats["by_date"]}
    dates = sorted({r["date"] for r in stats["by_date"]}, reverse=True)
    head = "".join(
        f"<th>{escape(v)}{'' if listed[v] else ' (unlisted)'}</th>" for v in versions)
    rows = ["<tr><th class=\"l\">date (UTC)</th>" + head + "<th>total</th></tr>"]
    for d in dates:
        counts = [by_cell.get((d, v), 0) for v in versions]
        rows.append(f"<tr>{_cell(d, 'l')}" + "".join(_cell(c or "") for c in counts)
                    + f"{_cell(sum(counts))}</tr>")
    totals = {t["version"]: t["count"] for t in stats["totals"]}
    rows.append('<tr><th class="l">total</th>'
                + "".join(f"<th>{totals[v]}</th>" for v in versions)
                + f"<th>{sum(totals.values())}</th></tr>")
    return "<table>" + "".join(rows) + "</table>"


def _failures_table(failures: list[dict]) -> str:
    if not failures:
        return "<p>No failure reports.</p>"
    rows = ['<tr><th class="l">reported (UTC)</th><th class="l">version</th>'
            '<th class="l">from</th><th class="l">stage</th><th class="l">detail</th></tr>']
    for f in failures:
        rows.append("<tr>" + _cell(f["reported_at"], "l") + _cell(f["version"], "l")
                    + _cell(f["installed_from"], "l") + _cell(f["stage"], "l")
                    + _cell(f["detail"] or "", "l") + "</tr>")
    return "<table>" + "".join(rows) + "</table>"


def render(stats: dict, failures: list[dict]) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta name=\"robots\" content=\"noindex\"><title>boxmunge version-check stats</title>"
        f"<style>{STYLE}</style></head><body>"
        f"<h1>Checks per version, {escape(stats['since'])} to {escape(stats['until'])}</h1>"
        f"<p class=\"note\">{escape(NOTE)}</p>{_checks_table(stats)}"
        f"<h1>Recent failure reports ({len(failures)})</h1>{_failures_table(failures)}"
        "</body></html>")
