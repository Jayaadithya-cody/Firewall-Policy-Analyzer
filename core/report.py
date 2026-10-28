"""
PDF report generation + firewall improvement suggestions.

Builds a final audit report (score, findings, per-finding fixes, hardening
advice and a proposed hardened rule set) from the same data the dashboard uses.
"""
from collections import Counter
from datetime import datetime
from html import escape
from io import BytesIO
from typing import List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Preformatted
)

from core.detector import IssueType, Severity
from core.recommendations import RecommendationEngine, rule_to_iptables

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
    "LOW": "#16a34a", "INFO": "#2563eb",
}
REMOVE_TYPES = {
    IssueType.SHADOWED, IssueType.REDUNDANT, IssueType.UNUSED,
    IssueType.PROHIBITED_PORT, IssueType.BANNED_SOURCE, IssueType.SUSPICIOUS,
}
ADMIN_PORTS = {22, 23, 3389, 5900}


def _band(score: int) -> Tuple[str, str]:
    if score >= 80:
        return "High Compliance", "#16a34a"
    if score >= 60:
        return "Moderate Compliance", "#ca8a04"
    if score >= 40:
        return "Low Compliance", "#ea580c"
    return "Critical Compliance Risk", "#dc2626"


def _clean(text) -> str:
    """Make text safe for the built-in PDF fonts and reportlab markup."""
    text = str(text)
    for a, b in (("→", "->"), ("—", "-"), ("–", "-"), ("‘", "'"),
                 ("’", "'"), ("“", '"'), ("”", '"'), ("✓", "OK"), ("…", "...")):
        text = text.replace(a, b)
    return escape(text.encode("latin-1", "replace").decode("latin-1"))


# ---------------------------------------------------------------- suggestions
def _port_of(rule) -> Optional[Tuple[int, int]]:
    p = rule.dst_port
    return (p.start, p.end) if p else None


def general_suggestions(rules, anomaly_findings, policy_findings) -> List[Tuple[str, str, str]]:
    """Return a list of (priority, title, advice) tailored to this configuration."""
    parsed = [r for r in rules if r.is_parsed]
    findings = list(anomaly_findings) + list(policy_findings)
    types = Counter(f.issue_type for f in findings)
    out: List[Tuple[str, str, str]] = []

    last = parsed[-1] if parsed else None
    has_final_drop = bool(last and last.is_deny_rule and last.src_ip in ("0.0.0.0/0", "any", "")
                          and not last.dst_port and last.protocol.value in ("all", "any"))
    if not has_final_drop:
        out.append(("HIGH", "Add a default-deny rule",
                    "End each chain with an explicit catch-all DROP (e.g. '-A INPUT -j DROP') or set the "
                    "chain policy to DROP ('iptables -P INPUT DROP'). Anything not explicitly allowed is then blocked."))

    if not any(r.state for r in parsed):
        out.append(("HIGH", "Use stateful filtering",
                    "Allow only return traffic of connections you started: "
                    "'-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' near the top, and drop INVALID packets "
                    "('-A INPUT -m state --state INVALID -j DROP')."))

    exposed_admin = [r for r in parsed if r.is_allow_rule and r.src_ip in ("0.0.0.0/0", "any", "")
                     and r.dst_port and any(r.dst_port.start <= p <= r.dst_port.end for p in ADMIN_PORTS)]
    if exposed_admin:
        nums = ", ".join(str(r.rule_number) for r in exposed_admin)
        out.append(("CRITICAL", "Do not expose administration ports to the Internet",
                    f"Rules {nums} allow SSH/Telnet/RDP/VNC from any address. Restrict them to an admin network, "
                    "or put them behind a VPN / bastion host. Replace Telnet with SSH and use key-based logins."))
        out.append(("MEDIUM", "Rate-limit remote logins",
                    "Throttle new SSH connections, e.g. '-A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set' "
                    "plus '-m recent --update --seconds 60 --hitcount 4 -j DROP', or run fail2ban."))

    if types[IssueType.SUSPICIOUS]:
        out.append(("CRITICAL", "Remove catch-all ACCEPT rules",
                    "A rule that accepts everything cancels the whole rule set. Delete it or give it explicit "
                    "source, destination, protocol and port."))

    if types[IssueType.SHADOWED] or types[IssueType.REDUNDANT] or types[IssueType.UNUSED]:
        n = types[IssueType.SHADOWED] + types[IssueType.REDUNDANT] + types[IssueType.UNUSED]
        out.append(("MEDIUM", "Clean up dead and duplicate rules",
                    f"{n} finding(s) are shadowed, redundant or unreachable rules. Removing them shortens the rule "
                    "list, speeds up packet matching and makes audits easier."))

    if types[IssueType.CONFLICTING]:
        out.append(("HIGH", "Resolve conflicting rules",
                    f"{types[IssueType.CONFLICTING]} conflicting ACCEPT/DROP pair(s) found. Put the more specific "
                    "rule first and make sure the intended action wins; document the intent in a comment."))

    if types[IssueType.PROHIBITED_PORT] or types[IssueType.BANNED_SOURCE]:
        out.append(("CRITICAL", "Enforce the organization policy",
                    "Close ports the policy prohibits and block banned sources. If an exception is really needed, "
                    "record who approved it, why, and when it expires."))

    if not any(r.action.value == "LOG" for r in parsed) or types[IssueType.MISSING_LOGGING]:
        out.append(("MEDIUM", "Enable logging for sensitive and dropped traffic",
                    "Add rate-limited LOG rules before the final DROP and before sensitive services, e.g. "
                    "'-A INPUT -m limit --limit 5/min -j LOG --log-prefix \"FW-DROP: \"'. Ship logs to a central server."))

    if parsed and sum(1 for r in parsed if not r.comment) > len(parsed) / 2:
        out.append(("LOW", "Document every rule",
                    "Most rules have no comment. Add '-m comment --comment \"owner / purpose / ticket\"' so that "
                    "future reviewers know why each rule exists."))

    # Always-useful hardening
    out.extend([
        ("MEDIUM", "Block spoofed and bogus traffic",
         "Drop packets arriving from the Internet with private/loopback source addresses (10/8, 172.16/12, 192.168/16, "
         "127/8) and invalid TCP flag combinations. Enable reverse-path filtering (rp_filter)."),
        ("LOW", "Limit ICMP and SYN floods",
         "Allow only needed ICMP types (echo-request rate-limited) and protect against SYN floods with "
         "'-m limit' or SYN cookies (net.ipv4.tcp_syncookies=1)."),
        ("LOW", "Do not forget OUTPUT, FORWARD and IPv6",
         "Review every chain, not only INPUT. Restrict outbound traffic from servers to what they need, and "
         "mirror the policy in ip6tables if IPv6 is enabled."),
        ("LOW", "Manage the rule base like code",
         "Keep the rules in version control, review changes before deployment, back up the working config and "
         "re-run this analysis after every change and at least quarterly."),
    ])
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    out.sort(key=lambda t: order.get(t[0], 9))
    return out


def build_optimized_ruleset(rules, anomaly_findings, policy_findings, policy=None):
    """
    Propose a cleaned-up rule set.
    Returns (lines, notes) where lines is a list of iptables rule strings and
    notes is a list of human-readable descriptions of what changed.
    """
    parsed = [r for r in rules if r.is_parsed]
    findings = list(anomaly_findings) + list(policy_findings)
    engine = RecommendationEngine(policy)
    by_num = {r.rule_number: r for r in parsed}
    notes: List[str] = []

    removed = {}
    for f in findings:
        if (f.issue_type in REMOVE_TYPES and f.rule_number in by_num
                and by_num[f.rule_number].action.value != "LOG"):
            removed.setdefault(f.rule_number, f.issue_type.value.replace("_", " "))

    replaced = {}
    for f in findings:
        n = f.rule_number
        if n in removed or n in replaced or n not in by_num:
            continue
        try:
            _, fix = engine.generate_recommendation(f, by_num[n], parsed)
        except Exception:
            fix = None
        if fix is not None:
            replaced[n] = fix

    lines: List[str] = []
    seen = set()

    def add(line):
        if line not in seen:
            seen.add(line)
            lines.append(line)

    raw_all = " ".join(r.raw_rule for r in parsed)
    has_loopback = "-i lo" in raw_all
    has_established = any("ESTABLISHED" in ",".join(r.state).upper() for r in parsed)
    if not has_loopback:
        add("-A INPUT -i lo -j ACCEPT")
        notes.append("Added: accept loopback traffic.")
    if not has_established:
        add("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
        add("-A INPUT -m state --state INVALID -j DROP")
        notes.append("Added: stateful rules (accept ESTABLISHED/RELATED, drop INVALID).")

    for r in parsed:
        n = r.rule_number
        if n in removed:
            notes.append(f"Removed rule {n} ({removed[n]}).")
            continue
        if n in replaced:
            new = rule_to_iptables(replaced[n])
            if new != rule_to_iptables(r):
                notes.append(f"Rewrote rule {n}: tightened to '{new}'.")
                add(new)
                continue
        if r.action.value == "LOG":
            continue  # logging rules are re-added in front of the final DROP
        add(r.raw_rule.strip())

    log_rules = [r.raw_rule.strip() for r in parsed if r.action.value == "LOG"]
    for lr in log_rules:
        add(lr)
    if not log_rules:
        add('-A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW-DROP: "')
        notes.append("Added: rate-limited logging of traffic that is about to be dropped.")

    lines = [l for l in lines if l != "-A INPUT -j DROP"]
    lines.append("-A INPUT -j DROP")
    if not any(l.strip() == "-A INPUT -j DROP" for l in [r.raw_rule.strip() for r in parsed]):
        notes.append("Added: final catch-all DROP (default deny).")
    return lines, notes


# ----------------------------------------------------------------------- PDF
def _styles():
    ss = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle("t", parent=ss["Title"], fontSize=24, leading=28, textColor=colors.HexColor("#111827"),
                                spaceAfter=4, alignment=0),
        "sub": ParagraphStyle("s", parent=ss["Normal"], fontSize=10, textColor=colors.HexColor("#6b7280")),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontSize=15, textColor=colors.HexColor("#111827"),
                             spaceBefore=14, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontSize=11.5, textColor=colors.HexColor("#111827"),
                             spaceBefore=8, spaceAfter=3),
        "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5, leading=13),
        "small": ParagraphStyle("sm", parent=ss["Normal"], fontSize=8.5, leading=11),
        "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=8, leading=10),
        "code": ParagraphStyle("code", parent=ss["Code"], fontName="Courier", fontSize=8, leading=10,
                               backColor=colors.HexColor("#f3f4f6"), borderPadding=4),
        "center": ParagraphStyle("ctr", parent=ss["Normal"], alignment=TA_CENTER),
    }
    return s


def _sev_chart(counts) -> Drawing:
    d = Drawing(440, 150)
    ch = VerticalBarChart()
    ch.x, ch.y, ch.width, ch.height = 40, 25, 380, 100
    ch.data = [[counts.get(s, 0) for s in SEV_ORDER]]
    ch.categoryAxis.categoryNames = SEV_ORDER
    ch.categoryAxis.labels.fontSize = 8
    ch.valueAxis.labels.fontSize = 8
    ch.valueAxis.valueMin = 0
    top = max(counts.values()) if counts else 1
    ch.valueAxis.valueMax = top + max(1, top // 5)
    ch.valueAxis.valueStep = max(1, (top + 4) // 5)
    ch.bars[0].fillColor = colors.HexColor("#2563eb")
    for i, sname in enumerate(SEV_ORDER):
        ch.bars[(0, i)].fillColor = colors.HexColor(SEV_COLORS[sname])
    ch.barLabelFormat = "%d"
    ch.barLabels.nudge = 7
    ch.barLabels.fontSize = 8
    d.add(ch)
    d.add(String(220, 138, "Findings by severity", fontSize=9, textAnchor="middle"))
    return d


def generate_pdf_report(rules, anomaly_findings, policy_findings, score, details,
                        policy=None, rules_text: str = "", comparison=None) -> bytes:
    st = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="Firewall Security Audit Report", author="Firewall Policy Analyzer")
    parsed = [r for r in rules if r.is_parsed]
    findings = list(anomaly_findings) + list(policy_findings)
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    findings_sorted = sorted(findings, key=lambda f: (sev_rank.get(f.severity.value, 9), f.rule_number))
    counts = Counter(f.severity.value for f in findings)
    label, band_color = _band(score)
    policy_name = getattr(policy, "name", "N/A") if policy else "N/A"
    by_num = {r.rule_number: r for r in parsed}
    engine = RecommendationEngine(policy)

    E = []
    E.append(Paragraph("Firewall Security Audit Report", st["title"]))
    E.append(Paragraph(_clean(f"Generated {datetime.now():%Y-%m-%d %H:%M} | Policy profile: {policy_name} | "
                              f"Rules analysed: {len(parsed)}"), st["sub"]))
    E.append(Spacer(1, 8))

    # --- score + summary
    score_tbl = Table([[Paragraph(f'<font size="30" color="{band_color}"><b>{score}%</b></font>',
                                  ParagraphStyle("sc", parent=st["center"], leading=36)),
                        Paragraph(f'<font size="13" color="{band_color}"><b>{_clean(label)}</b></font><br/>'
                                  f'<font size="9">{len(findings)} findings in total: '
                                  f'{len(anomaly_findings)} firewall anomalies and {len(policy_findings)} policy violations.</font>',
                                  st["body"])]],
                      colWidths=[40 * mm, 130 * mm])
    score_tbl.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(band_color)),
                                   ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                   ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
                                   ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    E.append(score_tbl)
    E.append(Spacer(1, 8))

    sev_tbl = Table([SEV_ORDER, [counts.get(s, 0) for s in SEV_ORDER]], colWidths=[34 * mm] * 5)
    ts = [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
          ("FONTSIZE", (0, 0), (-1, 0), 8), ("FONTSIZE", (0, 1), (-1, 1), 14), ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold")]
    for i, s in enumerate(SEV_ORDER):
        ts.append(("TEXTCOLOR", (i, 0), (i, 1), colors.HexColor(SEV_COLORS[s])))
    sev_tbl.setStyle(TableStyle(ts))
    E.append(sev_tbl)
    E.append(Spacer(1, 6))
    E.append(_sev_chart(counts))
    E.append(Paragraph(_clean("How the score works: every finding adds a penalty (Critical 10, High 5, Medium 2, Low 1). "
                              "The score falls as the penalty grows relative to the number of rules; 100% means no findings."),
                       st["small"]))

    if comparison:
        E.append(Paragraph("Before / After Comparison", st["h1"]))
        E.append(Paragraph(_clean(
            f"Compliance score: {comparison['before_score']}% -> {comparison['after_score']}%. "
            f"Findings: {comparison['before_count']} -> {comparison['after_count']}. "
            f"Resolved: {len(comparison['resolved'])}. New: {len(comparison['new'])}. "
            f"Still present: {len(comparison['remaining'])}."), st["body"]))

    # --- priority actions
    E.append(Paragraph("1. Priority Action Plan", st["h1"]))
    sugg = general_suggestions(rules, anomaly_findings, policy_findings)
    top = [s for s in sugg if s[0] in ("CRITICAL", "HIGH")][:6] or sugg[:4]
    if top:
        for pr, title, advice in top:
            E.append(Paragraph(f'<font color="{SEV_COLORS[pr]}"><b>[{pr}]</b></font> <b>{_clean(title)}</b> - {_clean(advice)}',
                               st["body"]))
            E.append(Spacer(1, 3))
    else:
        E.append(Paragraph("No urgent actions. Keep reviewing the rule base regularly.", st["body"]))

    # --- findings table
    E.append(Paragraph("2. Findings Overview", st["h1"]))
    if findings_sorted:
        rows = [["Rule", "Severity", "Type", "Description"]]
        for f in findings_sorted:
            rows.append([str(f.rule_number), f.severity.value,
                         Paragraph(_clean(f.issue_type.value.replace("_", " ").title()), st["cell"]),
                         Paragraph(_clean(f.description), st["cell"])])
        t = Table(rows, colWidths=[12 * mm, 20 * mm, 30 * mm, 112 * mm], repeatRows=1)
        style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                 ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 8),
                 ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
                 ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")])]
        for i, f in enumerate(findings_sorted, 1):
            style.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor(SEV_COLORS[f.severity.value])))
            style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
        t.setStyle(TableStyle(style))
        E.append(t)
    else:
        E.append(Paragraph("No findings - the configuration passed every check.", st["body"]))

    # --- detailed findings
    E.append(Paragraph("3. Detailed Findings and Recommended Fixes", st["h1"]))
    for i, f in enumerate(findings_sorted, 1):
        rule = by_num.get(f.rule_number)
        block = [Paragraph(f'<font color="{SEV_COLORS[f.severity.value]}"><b>{f.severity.value}</b></font> - '
                           f'Rule {f.rule_number}: {_clean(f.title)}', st["h2"]),
                 Paragraph(f"<b>Type:</b> {_clean(f.issue_type.value.replace('_', ' ').title())}", st["small"])]
        if rule is not None:
            block.append(Paragraph("<b>Rule:</b>", st["small"]))
            block.append(Preformatted(_plain(rule.raw_rule), st["code"]))
        block.append(Paragraph(f"<b>Problem:</b> {_clean(f.description)}", st["small"]))
        rec, fix = f.recommendation, None
        if rule is not None:
            try:
                rec, fix = engine.generate_recommendation(f, rule, parsed)
            except Exception:
                rec, fix = f.recommendation, None
        if "Recommendation:" in rec:
            rec = rec.split("Recommendation:", 1)[1].strip()
        if fix is not None and rule is not None and rule_to_iptables(fix) == rule_to_iptables(rule):
            fix = None  # identical to the current rule - nothing to change
        block.append(Paragraph(f"<b>Recommendation:</b> {_clean(rec)}", st["small"]))
        if fix is not None:
            block.append(Paragraph("<b>Suggested replacement rule:</b>", st["small"]))
            block.append(Preformatted(_plain(rule_to_iptables(fix)), st["code"]))
        if f.related_rules:
            block.append(Paragraph(f"<b>Related rules:</b> {', '.join(map(str, f.related_rules))}", st["small"]))
        block.append(Spacer(1, 4))
        E.append(KeepTogether(block))

    # --- suggestions
    E.append(Paragraph("4. Suggestions to Make the Firewall Better", st["h1"]))
    rows = [["Priority", "Suggestion", "Details"]]
    for pr, title, advice in sugg:
        rows.append([pr, Paragraph(f"<b>{_clean(title)}</b>", st["cell"]), Paragraph(_clean(advice), st["cell"])])
    t = Table(rows, colWidths=[20 * mm, 45 * mm, 109 * mm], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db"))]
    for i, (pr, _, _) in enumerate(sugg, 1):
        style += [("TEXTCOLOR", (0, i), (0, i), colors.HexColor(SEV_COLORS[pr])), ("FONTNAME", (0, i), (0, i), "Helvetica-Bold")]
    t.setStyle(TableStyle(style))
    E.append(t)

    # --- optimized ruleset
    E.append(Paragraph("5. Proposed Improved Rule Set", st["h1"]))
    lines, notes = build_optimized_ruleset(rules, anomaly_findings, policy_findings, policy)
    E.append(Paragraph("Automatically generated starting point. Review every line and test it on a non-production "
                       "system before applying; conflicting rules and logging requirements may still need manual decisions.",
                       st["small"]))
    E.append(Spacer(1, 4))
    for n in notes:
        E.append(Paragraph("- " + _clean(n), st["small"]))
    E.append(Spacer(1, 4))
    E.append(Preformatted("\n".join(_plain(l) for l in lines), st["code"]))

    # --- appendix
    E.append(PageBreak())
    E.append(Paragraph("Appendix A - Original Rules (input)", st["h1"]))
    E.append(Preformatted(_plain(rules_text.strip() or "\n".join(r.raw_rule for r in parsed)), st["code"]))
    unparsed = [r for r in rules if not r.is_parsed and r.raw_rule.strip()]
    if unparsed:
        E.append(Paragraph("Lines that could not be parsed", st["h2"]))
        E.append(Preformatted("\n".join(_plain(r.raw_rule) for r in unparsed), st["code"]))

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawString(18 * mm, 9 * mm, "Firewall Policy Analyzer - Audit Report")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(E, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def _plain(text) -> str:
    """Plain text for Preformatted blocks (no markup escaping needed, but keep latin-1 safe)."""
    text = str(text)
    for a, b in (("—", "-"), ("–", "-"), ("→", "->"), ("’", "'"), ("“", '"'), ("”", '"')):
        text = text.replace(a, b)
    return text.encode("latin-1", "replace").decode("latin-1")
