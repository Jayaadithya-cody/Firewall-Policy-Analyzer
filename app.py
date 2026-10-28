"""
Firewall Policy Anomaly, Compliance & Optimization Checker
Main Streamlit Application — Phase 8: Professional Dashboard
"""
import streamlit as st
import pandas as pd
from pathlib import Path
import sys
from collections import Counter
from html import escape as _esc
import altair as alt


def _st_version():
    try:
        return tuple(int(p) for p in st.__version__.split(".")[:2])
    except Exception:
        return (0, 0)


# Streamlit >= 1.50 uses width="stretch"; older versions use use_container_width=True.
# (Newest versions removed use_container_width, older ones don't know width="stretch".)
STRETCH = {"width": "stretch"} if _st_version() >= (1, 50) else {"use_container_width": True}

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.parser import parse_iptables
from core.policy import create_sample_policies, OrganizationPolicy
from core.report import generate_pdf_report
from core.detector import AnomalyDetector, PolicyChecker, calculate_compliance_score, Finding, IssueType, Severity


# ============================================================
# PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="Firewall Policy Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': None,
        'Report a Bug': None,
        'About': "Firewall Policy Anomaly, Compliance & Optimization Checker — B.Tech CSE Project"
    }
)

# ============================================================
# CUSTOM CSS — PROFESSIONAL DESIGN
# ============================================================
st.markdown("""
<style>
    /* Header */
    .main-header {
        border-bottom: 2px solid rgba(128,128,128,0.35);
        padding-bottom: 1rem;
        margin-bottom: 1.5rem;
    }
    .main-header h1 {
        margin-bottom: 0.2rem;
    }
    .main-header p {
        color: #6b7280;
        margin: 0;
    }

    /* Metric cards */
    .metric-grid {
        display: flex;
        gap: 0.75rem;
        flex-wrap: wrap;
    }
    .metric-card {
        flex: 1;
        min-width: 120px;
        background: #ffffff;
        color: #111827;
        border: 1px solid #e5e7eb;
        border-radius: 0.5rem;
        padding: 1rem;
        text-align: center;
    }
    .metric-card .value {
        font-size: 1.75rem;
        font-weight: 700;
        line-height: 1;
        color: #111827;
    }
    .metric-card .label {
        font-size: 0.8rem;
        color: #6b7280;
        margin-top: 0.4rem;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .metric-card.critical .value { color: #dc2626; }
    .metric-card.high .value { color: #ea580c; }
    .metric-card.medium .value { color: #ca8a04; }
    .metric-card.low .value { color: #16a34a; }
    .metric-card.score .value { color: #2563eb; }
    .score-track { background: rgba(128,128,128,0.30); border-radius: 999px; height: 10px; margin: 0.75rem 0.5rem 0; overflow: hidden; }
    .score-fill { height: 100%; border-radius: 999px; }

    /* Finding cards */
    .finding-card {
        border-left: 4px solid;
        padding: 1rem;
        margin: 0.5rem 0;
        background: #f8fafc;
        color: #111827;
        border-radius: 0.25rem;
    }
    .severity-CRITICAL { border-color: #dc2626; }
    .severity-HIGH { border-color: #ea580c; }
    .severity-MEDIUM { border-color: #ca8a04; }
    .severity-LOW { border-color: #16a34a; }
    .severity-INFO { border-color: #2563eb; }

    /* Severity badge */
    .sev-badge {
        color: white;
        padding: 0.15rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        font-weight: 600;
    }

    /* Compliance gauge */
    .compliance-ring {
        text-align: center;
        padding: 1.5rem;
    }
    .compliance-score {
        font-size: 3rem;
        font-weight: 800;
        line-height: 1;
    }

    /* Section spacing */
    .section {
        margin-bottom: 2rem;
    }

    /* Table styling */
    .stDataFrame {
        border-radius: 0.5rem;
    }

    /* Code blocks */
    code {
        font-family: 'Consolas', 'Monaco', monospace;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================
def init_session_state():
    defaults = {
        'rules': [],
        'anomaly_findings': [],
        'policy_findings': [],
        'compliance_score': 0,
        'compliance_details': {},
        'selected_policy': None,
        'policy_name': "College / University",
        'rules_text': "",
        'analysis_done': False,
        # Phase 10: Before/After comparison state
        'before_state': None,
        'after_state': None,
        'comparison': None,
        'comparison_done': False,
        'working_rules': [],
        'change_history': [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


init_session_state()


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def load_builtin_policy(policy_key: str) -> OrganizationPolicy:
    """Load a built-in policy by key"""
    policies = create_sample_policies()
    return policies.get(policy_key, policies['college'])


def load_custom_policy(uploaded_file) -> OrganizationPolicy:
    """Load custom policy from uploaded YAML file"""
    try:
        yaml_content = uploaded_file.read().decode('utf-8-sig')
        return OrganizationPolicy.from_yaml(yaml_content)
    except UnicodeDecodeError:
        yaml_content = uploaded_file.read().decode('latin-1')
        return OrganizationPolicy.from_yaml(yaml_content)


def load_sample_rules() -> str:
    """Load sample rules from file"""
    sample_path = Path(__file__).parent / "data" / "samples" / "sample_rules.txt"
    return sample_path.read_text(encoding="utf-8")


def run_analysis(rules, policy):
    """Run both anomaly detection and policy checking"""
    detector = AnomalyDetector()
    anomaly_findings = detector.analyze(rules)

    checker = PolicyChecker(policy)
    policy_findings = checker.check(rules)

    score, details = calculate_compliance_score(rules, anomaly_findings, policy_findings)

    return anomaly_findings, policy_findings, score, details


def severity_color(severity: Severity) -> str:
    """Return hex color for severity"""
    colors = {
        Severity.CRITICAL: "#dc2626",
        Severity.HIGH: "#ea580c",
        Severity.MEDIUM: "#ca8a04",
        Severity.LOW: "#16a34a",
        Severity.INFO: "#2563eb",
    }
    return colors.get(severity, "#6b7280")


def severity_css_class(severity: Severity) -> str:
    return f"severity-{severity.value}"


def issue_category(finding: Finding) -> str:
    """Categorize finding as anomaly or policy violation"""
    policy_types = {
        IssueType.POLICY_VIOLATION,
        IssueType.PROHIBITED_PORT,
        IssueType.BANNED_SOURCE,
        IssueType.MISSING_ADMIN_RESTRICTION,
        IssueType.MISSING_LOGGING,
    }
    if finding.issue_type in policy_types:
        return "Policy Violation"
    return "Firewall Anomaly"


def compliance_interpretation(score: int) -> tuple:
    """Return (label, color) for compliance score interpretation"""
    if score >= 80:
        return ("High Compliance", "#16a34a")
    elif score >= 60:
        return ("Moderate Compliance", "#ca8a04")
    elif score >= 40:
        return ("Low Compliance", "#ea580c")
    else:
        return ("Critical Compliance Risk", "#dc2626")


def build_findings_dataframe(findings):
    """Build a pandas DataFrame from findings for table display"""
    rows = []
    for f in findings:
        rows.append({
            "Rule": f.rule_number,
            "Category": issue_category(f),
            "Issue": f.issue_type.value.replace('_', ' ').title(),
            "Severity": f.severity.value,
            "Description": f.description[:100] + ("..." if len(f.description) > 100 else ""),
        })
    return pd.DataFrame(rows)


def build_rules_dataframe(rules):
    """Build a pandas DataFrame from parsed rules"""
    rows = []
    for r in rules:
        if not r.is_parsed:
            continue
        rows.append({
            "Position": r.rule_number,
            "Chain": r.chain,
            "Protocol": r.protocol.value,
            "Source": r.src_ip,
            "Destination": r.dst_ip,
            "Src Port": str(r.src_port) if r.src_port else "any",
            "Dst Port": str(r.dst_port) if r.dst_port else "any",
            "Action": r.action.value,
        })
    return pd.DataFrame(rows)


# ============================================================
# PHASE 10: BEFORE/AFTER COMPARISON FUNCTIONS
# ============================================================
def create_state_snapshot(rules, anomaly_findings, policy_findings, compliance_score, compliance_details, label):
    """Create a snapshot of current analysis state for comparison"""
    return {
        'label': label,
        'rules_text': st.session_state.rules_text,
        'rules': [(r.rule_number, r.raw_rule, r.action.value, r.protocol.value, r.src_ip, r.dst_ip, r.src_port, r.dst_port) for r in rules if r.is_parsed],
        'anomaly_findings': anomaly_findings,
        'policy_findings': policy_findings,
        'compliance_score': compliance_score,
        'compliance_details': compliance_details,
    }


def compare_states(before_state, after_state):
    """Compare two analysis states and categorize findings"""
    def finding_key(f):
        return (f.rule_number, f.issue_type, f.severity)

    before_findings = before_state['anomaly_findings'] + before_state['policy_findings']
    after_findings = after_state['anomaly_findings'] + after_state['policy_findings']

    before_keys = {finding_key(f): f for f in before_findings}
    after_keys = {finding_key(f): f for f in after_findings}

    resolved = []
    remaining = []
    new = []

    # Resolved: in before but not in after
    for key, finding in before_keys.items():
        if key not in after_keys:
            resolved.append(finding)
        else:
            remaining.append(finding)

    # New: in after but not in before
    for key, finding in after_keys.items():
        if key not in before_keys:
            new.append(finding)

    return {
        'resolved': resolved,
        'remaining': remaining,
        'new': new,
        'before_score': before_state['compliance_score'],
        'after_score': after_state['compliance_score'],
        'before_count': len(before_findings),
        'after_count': len(after_findings),
    }


def generate_comparison_report(comp, before_state, after_state):
    """Generate a detailed comparison report for download"""
    lines = []
    lines.append("=" * 70)
    lines.append("FIREWALL POLICY ANALYZER — BEFORE/AFTER COMPARISON REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Policy: {st.session_state.policy_name}")
    lines.append("")
    lines.append(f"BEFORE: {before_state['label']}")
    lines.append(f"  Compliance Score: {before_state['compliance_score']}%")
    lines.append(f"  Total Findings: {comp['before_count']}")
    lines.append("")
    lines.append(f"AFTER: {after_state['label']}")
    lines.append(f"  Compliance Score: {after_state['compliance_score']}%")
    lines.append(f"  Total Findings: {comp['after_count']}")
    lines.append("")
    lines.append(f"Score Change: {comp['after_score'] - comp['before_score']:+d}%")
    lines.append(f"Finding Count Change: {comp['after_count'] - comp['before_count']:+d}")
    lines.append("")
    lines.append("-" * 70)
    lines.append("RESOLVED FINDINGS (Fixed by Changes)")
    lines.append("-" * 70)
    if comp['resolved']:
        for f in comp['resolved']:
            lines.append(f"  Rule {f.rule_number} | {f.issue_type.value} | {f.severity.value}")
            lines.append(f"    Title: {f.title}")
            lines.append(f"    Description: {f.description}")
            lines.append(f"    Recommendation: {f.recommendation}")
            if f.related_rules:
                lines.append(f"    Related Rules: {', '.join(map(str, f.related_rules))}")
            lines.append("")
    else:
        lines.append("  None")
    lines.append("")
    lines.append("-" * 70)
    lines.append("REMAINING FINDINGS (Still Present)")
    lines.append("-" * 70)
    if comp['remaining']:
        for f in comp['remaining']:
            lines.append(f"  Rule {f.rule_number} | {f.issue_type.value} | {f.severity.value}")
            lines.append(f"    Title: {f.title}")
            lines.append(f"    Description: {f.description}")
            lines.append(f"    Recommendation: {f.recommendation}")
            if f.related_rules:
                lines.append(f"    Related Rules: {', '.join(map(str, f.related_rules))}")
            lines.append("")
    else:
        lines.append("  None")
    lines.append("")
    lines.append("-" * 70)
    lines.append("NEW FINDINGS (Introduced by Changes)")
    lines.append("-" * 70)
    if comp['new']:
        for f in comp['new']:
            lines.append(f"  Rule {f.rule_number} | {f.issue_type.value} | {f.severity.value}")
            lines.append(f"    Title: {f.title}")
            lines.append(f"    Description: {f.description}")
            lines.append(f"    Recommendation: {f.recommendation}")
            if f.related_rules:
                lines.append(f"    Related Rules: {', '.join(map(str, f.related_rules))}")
            lines.append("")
    else:
        lines.append("  None")
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)
    return "\n".join(lines)


def pdf_file_name() -> str:
    return f"firewall_audit_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.pdf"


def build_pdf_bytes() -> bytes:
    """Build (and cache per analysis state) the PDF report for the current analysis."""
    ss = st.session_state
    key = (ss.rules_text, ss.policy_name, ss.compliance_score, len(ss.anomaly_findings),
           len(ss.policy_findings), bool(ss.comparison_done),
           len(ss.change_history))
    if ss.get("_pdf_key") == key and ss.get("_pdf_cache"):
        return ss._pdf_cache
    data = generate_pdf_report(
        ss.rules, ss.anomaly_findings, ss.policy_findings, ss.compliance_score,
        ss.compliance_details, ss.selected_policy, ss.rules_text,
        comparison=ss.comparison if ss.comparison_done else None,
    )
    ss._pdf_key, ss._pdf_cache = key, data
    return data


# Callbacks run BEFORE the widgets are re-created, so they may set widget state safely.
def _select_sample():
    st.session_state.input_method = "Load Sample"


def _select_banking():
    st.session_state.policy_select = "Banking / Financial"


# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("## 🛡️ Firewall Policy Analyzer")

    st.markdown("---")

    # Organization / Policy selection
    st.markdown("### Organization")

    policy_option = st.selectbox(
        "Select Policy Profile",
        ["College / University", "Corporate", "Banking / Financial", "Custom Policy"],
        index=0,
        key="policy_select",
        help="Choose the organization type whose security policy should be enforced"
    )

    policy = None
    policy_key_map = {
        "College / University": "college",
        "Corporate": "corporate",
        "Banking / Financial": "banking",
    }

    if policy_option in policy_key_map:
        policy = load_builtin_policy(policy_key_map[policy_option])
        st.session_state.policy_name = policy_option
    elif policy_option == "Custom Policy":
        uploaded_policy = st.file_uploader(
            "Upload Custom Policy (YAML)",
            type=["yaml", "yml"],
            help="Upload a YAML policy file"
        )
        if uploaded_policy:
            try:
                policy = load_custom_policy(uploaded_policy)
                st.session_state.policy_name = f"Custom: {policy.name}"
                st.success(f"Loaded: {policy.name}")
            except Exception as e:
                st.error("Invalid policy file. Please check the YAML format.")
                st.session_state.last_error = str(e)
                policy = load_builtin_policy("college")
        else:
            st.info("Please upload a custom policy YAML file")
            policy = load_builtin_policy("college")

    st.session_state.selected_policy = policy

    # Quick policy summary
    if policy:
        with st.expander("Organization Policy", expanded=False):
            st.markdown(f"**{policy.name}**")
            st.markdown(f"Type: `{policy.policy_type.value}`")
            st.markdown(f"Default Inbound: `{'Deny' if policy.default_deny_inbound else 'Allow'}`")
            st.markdown(f"Default Outbound: `{'Deny' if policy.default_deny_outbound else 'Allow'}`")
            if policy.prohibited_ports:
                st.markdown(f"Prohibited Ports: `{', '.join(map(str, policy.prohibited_ports))}`")
            st.markdown(f"Services: `{len(policy.services)}` | Zones: `{len(policy.zones)}`")

    st.markdown("---")

    # Firewall rules input
    st.markdown("### Firewall Configuration")

    input_method = st.radio(
        "Input Method",
        ["Upload File", "Load Sample", "Paste Rules"],
        key="input_method",
        horizontal=True
    )

    rules_text = ""
    if input_method == "Upload File":
        uploaded_file = st.file_uploader(
            "Upload iptables rules",
            type=["txt", "conf", "rules"],
            help="Upload a file containing iptables rules",
            key="fw_upload"
        )
        if uploaded_file:
            try:
                rules_text = uploaded_file.read().decode('utf-8-sig')
                st.success(f"Loaded: {len(rules_text)} chars")
            except Exception:
                st.error("Unable to read this file. Please check the file format.")
                rules_text = ""
        else:
            st.info("Upload a firewall rules file")

    elif input_method == "Load Sample":
        rules_text = load_sample_rules()
        st.success("Sample loaded (15 rules)")
        with st.expander("Preview"):
            st.code(rules_text[:500] + "..." if len(rules_text) > 500 else rules_text, language="text")

    else:  # Paste Rules
        rules_text = st.text_area(
            "Paste iptables rules",
            height=180,
            placeholder="-A INPUT -p tcp -s 0.0.0.0/0 --dport 22 -j ACCEPT\n-A INPUT -p tcp -s 10.0.0.0/24 --dport 80 -j ACCEPT",
            key="pasted_rules"
        )
        if rules_text.strip():
            st.success(f"Pasted: {len(rules_text)} chars")

    st.markdown("---")

    # Analyze button
    analyze_btn = st.button(
        "🔍 Analyze Firewall",
        type="primary",
        **STRETCH,
        disabled=not rules_text.strip()
    )

    if not rules_text.strip():
        st.caption("Provide firewall rules above to enable analysis.")


# ============================================================
# MAIN AREA
# ============================================================

# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ Firewall Policy Analyzer</h1>
    <p>Analyze firewall configurations for security anomalies and organization-specific policy violations.</p>
</div>
""", unsafe_allow_html=True)

# Filled at the end of the script (after any analysis in this run has finished)
export_slot = st.container()


# ============================================================
# ANALYSIS TRIGGER (Initial Analysis - sets BEFORE state)
# ============================================================
if analyze_btn and rules_text.strip():
    with st.spinner("Analyzing firewall rules..."):
        try:
            rules = parse_iptables(rules_text)
            if not any(r.is_parsed for r in rules):
                st.error("Unable to parse this firewall configuration. Please check the format.")
            else:
                anomaly_findings, policy_findings, score, details = run_analysis(
                    rules, st.session_state.selected_policy
                )
                st.session_state.rules = rules
                st.session_state.anomaly_findings = anomaly_findings
                st.session_state.policy_findings = policy_findings
                st.session_state.compliance_score = score
                st.session_state.compliance_details = details
                st.session_state.rules_text = rules_text
                st.session_state.analysis_done = True

                # Phase 10: Store BEFORE state (original analysis - never overwritten)
                if st.session_state.before_state is None:
                    st.session_state.before_state = create_state_snapshot(
                        rules, anomaly_findings, policy_findings, score, details, "Initial Analysis"
                    )
                    st.session_state.working_rules = rules.copy()
                    st.session_state.change_history = []

                st.success("Analysis complete!")

        except Exception as e:
            st.error("An error occurred during analysis. Please check your input.")
            st.session_state.last_error = str(e)


# ============================================================
# RE-ANALYSIS BUTTON (Phase 10 - sets AFTER state)
# ============================================================
if st.session_state.analysis_done and st.session_state.before_state is not None:
    st.divider()
    st.markdown("## 🔄 Re-Analyze After Changes")
    st.caption("Modify rules below, then click Re-Analyze to compare before/after states.")

    # Rule editor
    with st.expander("✏️ Edit Firewall Rules (Working Copy)", expanded=False):
        st.markdown("Edit the rules below. Each line should be an iptables rule.")
        edited_rules = st.text_area(
            "Working Rules",
            value=st.session_state.rules_text,
            height=200,
            key="working_rules_text",
            help="Modify rules here. The BEFORE state preserves the original analysis."
        )

    if st.button("🔁 Re-Analyze", type="primary", **STRETCH):
        with st.spinner("Re-analyzing firewall rules..."):
            try:
                new_rules = parse_iptables(edited_rules)
                if not any(r.is_parsed for r in new_rules):
                    st.error("Unable to parse the modified firewall configuration. Please check the format.")
                else:
                    anomaly_findings, policy_findings, score, details = run_analysis(
                        new_rules, st.session_state.selected_policy
                    )
                    st.session_state.rules = new_rules
                    st.session_state.anomaly_findings = anomaly_findings
                    st.session_state.policy_findings = policy_findings
                    st.session_state.compliance_score = score
                    st.session_state.compliance_details = details
                    st.session_state.rules_text = edited_rules

                    # Phase 10: Store AFTER state (latest re-analysis)
                    st.session_state.after_state = create_state_snapshot(
                        new_rules, anomaly_findings, policy_findings, score, details, "After Changes"
                    )

                    # Compare before and after
                    st.session_state.comparison = compare_states(
                        st.session_state.before_state, st.session_state.after_state
                    )
                    st.session_state.comparison_done = True

                    st.session_state.change_history.append({
                        'timestamp': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'rules_text': edited_rules,
                    })

                    st.success("Re-analysis complete! See comparison below.")
                    st.rerun()

            except Exception as e:
                st.error("An error occurred during re-analysis. Please check your input.")
                st.session_state.last_error = str(e)


# ============================================================
# RESULTS DISPLAY
# ============================================================
if st.session_state.analysis_done and st.session_state.rules:
    rules = st.session_state.rules
    anomaly_findings = st.session_state.anomaly_findings
    policy_findings = st.session_state.policy_findings
    score = st.session_state.compliance_score
    details = st.session_state.compliance_details

    all_findings = anomaly_findings + policy_findings

    # ============================================================
    # SECTION 1: AUDIT SUMMARY DASHBOARD
    # ============================================================
    st.markdown("## 📊 Audit Summary")
    st.caption(f"Policy: **{st.session_state.policy_name}** | Rules analyzed: **{details.get('total_rules', 0)}**")

    # Metric cards
    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="value">{details.get('total_rules', 0)}</div>
            <div class="label">Rules</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="value">{details.get('issues', 0)}</div>
            <div class="label">Total Issues</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="value">{details.get('anomaly_count', 0)}</div>
            <div class="label">Anomalies</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="value">{details.get('policy_violation_count', 0)}</div>
            <div class="label">Policy Viol.</div>
        </div>
        """, unsafe_allow_html=True)

    bd = details.get('breakdown', {})
    with col5:
        st.markdown(f"""
        <div class="metric-card critical">
            <div class="value">{bd.get('CRITICAL', 0)}</div>
            <div class="label">Critical</div>
        </div>
        """, unsafe_allow_html=True)

    with col6:
        st.markdown(f"""
        <div class="metric-card high">
            <div class="value">{bd.get('HIGH', 0)}</div>
            <div class="label">High</div>
        </div>
        """, unsafe_allow_html=True)

    with col7:
        st.markdown(f"""
        <div class="metric-card score">
            <div class="value">{score}%</div>
            <div class="label">Compliance</div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # ============================================================
    # SECTION 2: COMPLIANCE SCORE + VISUALIZATIONS
    # ============================================================
    viz_col1, viz_col2, viz_col3 = st.columns([1, 2, 2])

    # Compliance score display
    with viz_col1:
        st.markdown("### Compliance Score")
        label, color = compliance_interpretation(score)
        st.markdown(f"""
        <div class="compliance-ring">
            <div class="compliance-score" style="color: {color};">{score}%</div>
            <div style="color: {color}; font-weight: 600; margin-top: 0.5rem;">{label}</div>
            <div class="score-track"><div class="score-fill" style="width: {max(2, score)}%; background: {color};"></div></div>
        </div>
        """, unsafe_allow_html=True)
        st.caption("Project-defined score (0–100), weighted by severity.")

    # Severity distribution chart
    SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    SEV_COLORS = ["#dc2626", "#ea580c", "#ca8a04", "#16a34a", "#2563eb"]
    with viz_col2:
        st.markdown("#### Findings by Severity")
        if all_findings:
            sev_counts = Counter(f.severity.value for f in all_findings)
            sev_df = pd.DataFrame({"Severity": SEV_ORDER,
                                   "Count": [sev_counts.get(x, 0) for x in SEV_ORDER]})
            base = alt.Chart(sev_df).encode(
                x=alt.X("Severity:N", sort=SEV_ORDER, axis=alt.Axis(labelAngle=0, title=None)),
                y=alt.Y("Count:Q", axis=alt.Axis(tickMinStep=1, title="Findings")),
            )
            bars = base.mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
                color=alt.Color("Severity:N", scale=alt.Scale(domain=SEV_ORDER, range=SEV_COLORS), legend=None),
                tooltip=["Severity", "Count"],
            )
            labels = base.mark_text(dy=-8, fontWeight="bold", color="#9ca3af").encode(text="Count:Q")
            st.altair_chart((bars + labels).properties(height=300), **STRETCH)
        else:
            st.info("No findings")

    # Issue type distribution chart
    with viz_col3:
        st.markdown("#### Findings by Type")
        if all_findings:
            type_counts = Counter(f.issue_type.value.replace('_', ' ').title() for f in all_findings)
            type_df = pd.DataFrame(list(type_counts.items()), columns=["Issue Type", "Count"]) \
                .sort_values("Count", ascending=False)
            order = type_df["Issue Type"].tolist()
            base = alt.Chart(type_df).encode(
                y=alt.Y("Issue Type:N", sort=order, axis=alt.Axis(title=None, labelLimit=220)),
                x=alt.X("Count:Q", axis=alt.Axis(tickMinStep=1, title="Findings")),
            )
            bars = base.mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#2563eb").encode(
                tooltip=["Issue Type", "Count"])
            labels = base.mark_text(align="left", dx=4, fontWeight="bold", color="#9ca3af").encode(text="Count:Q")
            st.altair_chart((bars + labels).properties(height=max(220, 30 * len(order))), **STRETCH)
        else:
            st.info("No findings")

    st.divider()

    # ============================================================
    # SECTION 3: FILTERS + FINDINGS TABLE
    # ============================================================
    st.markdown("## 🔍 Findings")

    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:
        category_filter = st.selectbox(
            "Category",
            ["All", "Firewall Anomaly", "Policy Violation"],
            key="cat_filter"
        )

    with filter_col2:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            key="sev_filter"
        )

    with filter_col3:
        # Dynamic issue type filter
        issue_types = sorted(set(f.issue_type.value.replace('_', ' ').title() for f in all_findings))
        issue_filter = st.selectbox(
            "Issue Type",
            ["All"] + issue_types,
            key="type_filter"
        )

    # Apply filters
    def apply_filters(findings):
        filtered = []
        for f in findings:
            cat_ok = (category_filter == "All" or issue_category(f) == category_filter)
            sev_ok = (severity_filter == "All" or f.severity.value == severity_filter)
            type_ok = (issue_filter == "All" or f.issue_type.value.replace('_', ' ').title() == issue_filter)
            if cat_ok and sev_ok and type_ok:
                filtered.append(f)
        return filtered

    filtered_findings = apply_filters(all_findings)

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    filtered_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.rule_number))

    if not filtered_findings:
        st.info("No findings match the current filters.")
    else:
        st.caption(f"Showing **{len(filtered_findings)}** of **{len(all_findings)}** findings")

        # Findings table
        findings_df = build_findings_dataframe(filtered_findings)
        # Color the severity column
        st.dataframe(
            findings_df,
            **STRETCH,
            column_config={
                "Rule": st.column_config.NumberColumn("Rule", width="small"),
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "Category": st.column_config.TextColumn("Category", width="medium"),
                "Issue": st.column_config.TextColumn("Issue", width="medium"),
                "Description": st.column_config.TextColumn("Description", width="large"),
            },
            hide_index=True,
        )

        st.divider()

        # ============================================================
        # SECTION 4: FINDING DETAILS
        # ============================================================
        st.markdown("### Finding Details")

        selected_idx = st.selectbox(
            "Select a finding to view details",
            range(len(filtered_findings)),
            format_func=lambda i: f"Rule {filtered_findings[i].rule_number} — {filtered_findings[i].issue_type.value.replace('_', ' ').title()} ({filtered_findings[i].severity.value})",
            key="finding_select_" + str(hash(tuple(
                (f.rule_number, f.issue_type.value, f.severity.value) for f in filtered_findings
            )))
        )

        if selected_idx is not None:
            finding = filtered_findings[selected_idx]
            cat = issue_category(finding)
            color = severity_color(finding.severity)

            # Header
            st.markdown(f"""
            <div class="finding-card {severity_css_class(finding.severity)}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="font-size: 1.1rem; font-weight: 700;">
                        Rule {finding.rule_number}
                    </div>
                    <div>
                        <span class="sev-badge" style="background: {color};">{finding.severity.value}</span>
                        <span class="sev-badge" style="background: #6b7280; margin-left: 0.5rem;">{cat}</span>
                    </div>
                </div>
                <div style="margin-top: 0.5rem; font-weight: 600; color: #374151;">
                    {_esc(finding.title)}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Detail grid
            detail_col1, detail_col2 = st.columns(2)

            with detail_col1:
                st.markdown("**Category**")
                st.write(cat)
                st.markdown("**Issue Type**")
                st.write(finding.issue_type.value.replace('_', ' ').title())
                st.markdown("**Severity**")
                st.write(finding.severity.value)

            with detail_col2:
                # Original rule
                rule_obj = next((r for r in rules if r.rule_number == finding.rule_number), None)
                if rule_obj:
                    st.markdown("**Original Rule**")
                    st.code(rule_obj.raw_rule, language="text")
                if finding.related_rules:
                    st.markdown("**Related Rules**")
                    st.write(", ".join(f"Rule {r}" for r in finding.related_rules))

            # Problem / Impact / Recommendation
            st.markdown("**Problem**")
            st.write(finding.description)

            st.markdown("**Security Impact**")
            impact_text = {
                Severity.CRITICAL: "This represents a critical security exposure that could lead to unauthorized access or system compromise.",
                Severity.HIGH: "This creates a significant security gap that should be addressed promptly.",
                Severity.MEDIUM: "This weakens the security posture and should be reviewed during routine maintenance.",
                Severity.LOW: "This is a minor issue with limited security impact.",
                Severity.INFO: "Informational finding.",
            }.get(finding.severity, "Review recommended.")
            st.warning(impact_text)

            st.markdown("**Recommendation**")
            st.success(finding.recommendation)

    st.divider()

    # ============================================================
    # SECTION 5: PARSED FIREWALL RULES
    # ============================================================
    with st.expander("👁️ View Parsed Firewall Rules", expanded=False):
        rules_df = build_rules_dataframe(rules)
        if not rules_df.empty:
            st.dataframe(rules_df, **STRETCH, hide_index=True)
        else:
            st.info("No parsed rules to display")

    # ============================================================
    # SECTION 6: ORGANIZATION POLICY
    # ============================================================
    with st.expander("📋 View Organization Policy", expanded=False):
        policy = st.session_state.selected_policy
        if policy:
            st.markdown(f"**Organization:** {policy.name}")
            st.markdown(f"**Type:** {policy.policy_type.value.title()}")

            pol_col1, pol_col2 = st.columns(2)
            with pol_col1:
                st.markdown("**Global Settings:**")
                st.markdown(f"- Default Inbound: `{'Deny' if policy.default_deny_inbound else 'Allow'}`")
                st.markdown(f"- Default Outbound: `{'Deny' if policy.default_deny_outbound else 'Allow'}`")
                st.markdown(f"- Logging Required: `{policy.require_logging}`")
                st.markdown(f"- Stateful Required: `{policy.require_stateful}`")
                if policy.prohibited_ports:
                    st.markdown(f"- **Prohibited Ports:** {', '.join(map(str, policy.prohibited_ports))}")
                if policy.banned_sources:
                    st.markdown(f"- **Banned Sources:** {', '.join(policy.banned_sources)}")

            with pol_col2:
                st.markdown("**Network Zones:**")
                for zone in policy.zones:
                    st.markdown(f"- {zone.name} (`{zone.cidr}`) — {zone.zone_type}")

            st.markdown("**Service Policies:**")
            for svc in policy.services:
                admin = " 🔐 **Admin-only**" if svc.requires_admin_access else ""
                allowed = ", ".join(svc.allowed_sources) if svc.allowed_sources else "Any"
                st.markdown(f"- **{svc.name}** (port {svc.port}/{svc.protocol.value}) — Allowed from: {allowed}{admin}")

    # ============================================================
    # SECTION 8: BEFORE/AFTER COMPARISON (Phase 10)
    # ============================================================
    if st.session_state.comparison_done and st.session_state.comparison:
        st.divider()
        st.markdown("## ⚖️ Before / After Comparison")
        st.caption("BEFORE = Original Analysis (never overwritten) | AFTER = Latest Re-Analysis")

        comp = st.session_state.comparison
        before_state = st.session_state.before_state
        after_state = st.session_state.after_state

        # Summary metrics
        met_col1, met_col2, met_col3, met_col4 = st.columns(4)
        with met_col1:
            delta = comp['after_score'] - comp['before_score']
            color = "#16a34a" if delta >= 0 else "#dc2626"
            st.markdown(f"""
            <div class="metric-card">
                <div class="value" style="color: {color};">{comp['before_score']}% → {comp['after_score']}%</div>
                <div class="label">Compliance Score</div>
            </div>
            """, unsafe_allow_html=True)
        with met_col2:
            delta = comp['after_count'] - comp['before_count']
            color = "#16a34a" if delta <= 0 else "#dc2626"
            st.markdown(f"""
            <div class="metric-card">
                <div class="value" style="color: {color};">{comp['before_count']} → {comp['after_count']}</div>
                <div class="label">Total Findings</div>
            </div>
            """, unsafe_allow_html=True)
        with met_col3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="value" style="color: #16a34a;">{len(comp['resolved'])}</div>
                <div class="label">Resolved</div>
            </div>
            """, unsafe_allow_html=True)
        with met_col4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="value" style="color: #ea580c;">{len(comp['new'])}</div>
                <div class="label">New Findings</div>
            </div>
            """, unsafe_allow_html=True)

        st.divider()

        # Resolved findings
        if comp['resolved']:
            st.markdown("### ✅ Resolved Findings")
            for f in comp['resolved']:
                color = severity_color(f.severity)
                st.markdown(f"""
                <div class="finding-card {severity_css_class(f.severity)}" style="opacity: 0.7;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div><strong>Rule {f.rule_number}</strong> — {f.issue_type.value.replace('_', ' ').title()}</div>
                        <div><span class="sev-badge" style="background: {color};">{f.severity.value}</span></div>
                    </div>
                    <div style="margin-top: 0.5rem; color: #16a34a;"><strong>✓ RESOLVED</strong></div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem;"><strong>Category:</strong> {_esc(f.title)}</div>
                    <div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Description:</strong> {_esc(f.description)}</div>
                    <div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Recommendation:</strong> {_esc(f.recommendation)}</div>
                    {f'<div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Related Rules:</strong> {", ".join(map(str, f.related_rules))}</div>' if f.related_rules else ''}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.caption("No resolved findings")

        # Remaining findings
        if comp['remaining']:
            st.markdown("### ⚠️ Remaining Findings")
            for f in comp['remaining']:
                color = severity_color(f.severity)
                st.markdown(f"""
                <div class="finding-card {severity_css_class(f.severity)}">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div><strong>Rule {f.rule_number}</strong> — {f.issue_type.value.replace('_', ' ').title()}</div>
                        <div><span class="sev-badge" style="background: {color};">{f.severity.value}</span></div>
                    </div>
                    <div style="margin-top: 0.5rem; color: #ca8a04;"><strong>⟳ Still present</strong></div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem;"><strong>Category:</strong> {_esc(f.title)}</div>
                    <div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Description:</strong> {_esc(f.description)}</div>
                    <div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Recommendation:</strong> {_esc(f.recommendation)}</div>
                    {f'<div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Related Rules:</strong> {", ".join(map(str, f.related_rules))}</div>' if f.related_rules else ''}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.caption("No remaining findings")

        # New findings
        if comp['new']:
            st.markdown("### 🆕 New Findings Introduced")
            for f in comp['new']:
                color = severity_color(f.severity)
                st.markdown(f"""
                <div class="finding-card {severity_css_class(f.severity)}" style="border-left-color: #ea580c;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div><strong>Rule {f.rule_number}</strong> — {f.issue_type.value.replace('_', ' ').title()}</div>
                        <div><span class="sev-badge" style="background: {color};">{f.severity.value}</span></div>
                    </div>
                    <div style="margin-top: 0.5rem; color: #ea580c;"><strong>⚠ NEW — introduced by changes</strong></div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem;"><strong>Category:</strong> {_esc(f.title)}</div>
                    <div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Description:</strong> {_esc(f.description)}</div>
                    <div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Recommendation:</strong> {_esc(f.recommendation)}</div>
                    {f'<div style="margin-top: 0.25rem; font-size: 0.9rem;"><strong>Related Rules:</strong> {", ".join(map(str, f.related_rules))}</div>' if f.related_rules else ''}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.caption("No new findings introduced")

        # Download comparison report
        st.divider()
        report = generate_comparison_report(comp, before_state, after_state)
        st.download_button(
            label="📥 Download Comparison Report",
            data=report,
            file_name=f"firewall_comparison_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            **STRETCH
        )

        # Change history
        if st.session_state.change_history:
            with st.expander("📜 Change History", expanded=False):
                for i, change in enumerate(st.session_state.change_history, 1):
                    st.markdown(f"**Change #{i}** — {change['timestamp']}")
                    st.code(change['rules_text'][:500] + "..." if len(change['rules_text']) > 500 else change['rules_text'], language="text")

    # ============================================================
    # SECTION 9: DEMO MODE / SAMPLE LOADING
    # ============================================================
    st.divider()
    st.markdown("## 🎯 Try Sample Configuration")
    st.caption("Quick way to demonstrate the analyzer during a viva.")

    demo_col1, demo_col2 = st.columns(2)
    with demo_col1:
        st.button("📂 Load Sample Firewall", on_click=_select_sample, **STRETCH)
    with demo_col2:
        st.button("🔄 Switch to Banking Policy", on_click=_select_banking, **STRETCH)

    if not st.session_state.rules_text:
        st.info("Click 'Load Sample Firewall' above, then 'Analyze Firewall' in the sidebar.")

    # ============================================================
    # SECTION 10: FINAL REPORT (PDF)
    # ============================================================
    st.divider()
    st.markdown("## 📄 Final Report")
    st.caption("Score, every finding with its fix, suggestions to make the firewall better, "
               "and a proposed improved rule set - as a PDF.")
    try:
        pdf_bytes = build_pdf_bytes()
        st.session_state.pdf_bytes = pdf_bytes
        st.download_button(
            "📄 Download Final Report (PDF)", data=pdf_bytes, file_name=pdf_file_name(),
            mime="application/pdf", type="primary", key="pdf_bottom", **STRETCH
        )
    except Exception as e:
        st.session_state.pdf_bytes = None
        st.error(f"Could not build the PDF report: {e}")

else:
    # ============================================================
    # WELCOME SCREEN
    # ============================================================
    st.markdown("""
    <div style="text-align: center; padding: 3rem 1rem;">
        <h2>Welcome to the Firewall Policy Analyzer</h2>
        <p style="color: #6b7280; max-width: 600px; margin: 0 auto;">
            Upload a firewall configuration and an organization policy to detect security anomalies,
            policy violations, and calculate a compliance score.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Feature cards
    feat_col1, feat_col2, feat_col3 = st.columns(3)

    with feat_col1:
        st.markdown("""
        ### 🔍 Anomaly Detection
        - Shadowed rules
        - Redundant rules
        - Conflicting rules
        - Overly permissive rules
        - Suspicious configurations
        """)

    with feat_col2:
        st.markdown("""
        ### 📋 Policy Compliance
        - Prohibited port detection
        - Banned source detection
        - Service restrictions
        - Admin-access enforcement
        - Logging requirements
        """)

    with feat_col3:
        st.markdown("""
        ### 📊 Reporting
        - Compliance score (0–100%)
        - Severity breakdown
        - Detailed recommendations
        - Policy switching
        - Export-ready findings
        """)

    st.divider()

    st.markdown("### 🚀 Quick Start")
    st.markdown("""
    1. **Select an organization policy** in the sidebar (College, Corporate, Banking, or Custom)
    2. **Provide firewall rules** — Upload a file, load the sample, or paste rules
    3. **Click Analyze Firewall** to view the audit dashboard
    """)


# ============================================================
# TOP-OF-PAGE EXPORT BUTTON (filled last so it always reflects the latest analysis)
# ============================================================
with export_slot:
    _c1, _c2 = st.columns([4, 1])
    with _c2:
        if st.session_state.analysis_done and st.session_state.get("pdf_bytes"):
            st.download_button("📄 Export PDF", data=st.session_state.pdf_bytes, file_name=pdf_file_name(),
                               mime="application/pdf", type="primary", key="pdf_top", **STRETCH)
        else:
            st.button("📄 Export PDF", disabled=True, key="pdf_top_off", **STRETCH,
                      help="Run an analysis first - the PDF report is built from it.")


# ============================================================
# FOOTER
# ============================================================
st.markdown("---")
st.caption("🔥 Firewall Policy Anomaly, Compliance & Optimization Checker — B.Tech CSE Project")
