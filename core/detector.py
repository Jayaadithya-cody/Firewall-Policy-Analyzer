"""
Generic Firewall Rule Anomaly Detection
Detects shadowed, redundant, conflicting, and overly permissive rules.
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum
from core.rule import FirewallRule, Action, Protocol, PortRange
from core.policy import OrganizationPolicy


class Severity(Enum):
    """Issue severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IssueType(Enum):
    """Types of issues detected"""
    # Generic anomalies
    SHADOWED = "shadowed"
    REDUNDANT = "redundant"
    CONFLICTING = "conflicting"
    OVERLY_PERMISSIVE = "overly_permissive"
    SUSPICIOUS = "suspicious"
    UNUSED = "unused"
    # Policy violations
    POLICY_VIOLATION = "policy_violation"
    PROHIBITED_PORT = "prohibited_port"
    BANNED_SOURCE = "banned_source"
    MISSING_ADMIN_RESTRICTION = "missing_admin_restriction"
    MISSING_LOGGING = "missing_logging"


@dataclass
class Finding:
    """Represents a detected issue"""
    rule_number: int
    issue_type: IssueType
    severity: Severity
    title: str
    description: str
    recommendation: str
    related_rules: List[int] = None  # Other rule numbers involved

    def __post_init__(self):
        if self.related_rules is None:
            self.related_rules = []


class AnomalyDetector:
    """Detects generic firewall rule anomalies"""

    def __init__(self):
        self.findings: List[Finding] = []

    def analyze(self, rules: List[FirewallRule]) -> List[Finding]:
        """Run all detection algorithms"""
        self.findings = []

        # Only analyze parsed rules in the same chain
        valid_rules = [r for r in rules if r.is_parsed and r.chain == "INPUT"]
        if not valid_rules:
            valid_rules = [r for r in rules if r.is_parsed]

        # Sort by rule number (processing order)
        valid_rules.sort(key=lambda r: rule_number_sort_key(r.rule_number))

        # Run detectors
        self._detect_shadowed_rules(valid_rules)
        self._detect_redundant_rules(valid_rules)
        self._detect_conflicting_rules(valid_rules)
        self._detect_overly_permissive(valid_rules)
        self._detect_suspicious_rules(valid_rules)
        self._detect_unused_rules(valid_rules)

        return self.findings

    def _detect_shadowed_rules(self, rules: List[FirewallRule]):
        """Detect rules that are completely shadowed by earlier rules"""
        for i, rule in enumerate(rules):
            if not rule.is_parsed:
                continue

            # Check if any earlier rule completely covers this rule
            for j in range(i):
                earlier = rules[j]
                if not earlier.is_parsed:
                    continue

                if self._rule_covers(earlier, rule):
                    self.findings.append(Finding(
                        rule_number=rule.rule_number,
                        issue_type=IssueType.SHADOWED,
                        severity=Severity.HIGH,
                        title=f"Rule {rule.rule_number} is shadowed by Rule {earlier.rule_number}",
                        description=(
                            f"Rule {earlier.rule_number} ({earlier.action.value}) matches all traffic "
                            f"that Rule {rule.rule_number} ({rule.action.value}) would match. "
                            f"Rule {rule.rule_number} will never be reached."
                        ),
                        recommendation=(
                            f"Remove Rule {rule.rule_number} or reorder rules if intentional. "
                            f"Shadowed rules waste processing and create confusion."
                        ),
                        related_rules=[earlier.rule_number]
                    ))
                    break  # Only report first shadowing rule

    def _detect_redundant_rules(self, rules: List[FirewallRule]):
        """Detect duplicate or redundant rules"""
        for i, rule1 in enumerate(rules):
            if not rule1.is_parsed:
                continue

            for j in range(i + 1, len(rules)):
                rule2 = rules[j]
                if not rule2.is_parsed:
                    continue

                if self._rules_equivalent(rule1, rule2):
                    self.findings.append(Finding(
                        rule_number=rule2.rule_number,
                        issue_type=IssueType.REDUNDANT,
                        severity=Severity.MEDIUM,
                        title=f"Rule {rule2.rule_number} is redundant with Rule {rule1.rule_number}",
                        description=(
                            f"Rule {rule2.rule_number} has identical matching criteria as "
                            f"Rule {rule1.rule_number}. Both have action {rule1.action.value}."
                        ),
                        recommendation=f"Remove Rule {rule2.rule_number} as it duplicates Rule {rule1.rule_number}.",
                        related_rules=[rule1.rule_number]
                    ))

    def _detect_conflicting_rules(self, rules: List[FirewallRule]):
        """Detect rules with overlapping criteria but different actions"""
        for i, rule1 in enumerate(rules):
            if not rule1.is_parsed or not rule1.is_allow_rule() and not rule1.is_deny_rule():
                continue

            for j in range(i + 1, len(rules)):
                rule2 = rules[j]
                if not rule2.is_parsed or not rule2.is_allow_rule() and not rule2.is_deny_rule():
                    continue

                # Check for conflict: overlapping match but different actions
                if (rule1.action != rule2.action and
                    self._rules_overlap(rule1, rule2)):
                    # The earlier rule takes precedence
                    severity = Severity.HIGH if rule1.is_allow_rule() and rule2.is_deny_rule() else Severity.MEDIUM
                    self.findings.append(Finding(
                        rule_number=rule2.rule_number,
                        issue_type=IssueType.CONFLICTING,
                        severity=severity,
                        title=f"Rule {rule2.rule_number} conflicts with Rule {rule1.rule_number}",
                        description=(
                            f"Rule {rule1.rule_number} ({rule1.action.value}) and "
                            f"Rule {rule2.rule_number} ({rule2.action.value}) match overlapping traffic. "
                            f"Since Rule {rule1.rule_number} comes first, it takes precedence."
                        ),
                        recommendation=(
                            f"Review rule ordering. If {rule2.action.value} should take precedence, "
                            f"move Rule {rule2.rule_number} before Rule {rule1.rule_number}. "
                            f"Otherwise, narrow the match criteria to avoid overlap."
                        ),
                        related_rules=[rule1.rule_number]
                    ))

    def _detect_overly_permissive(self, rules: List[FirewallRule]):
        """Detect overly permissive rules (allow from anywhere to sensitive ports)"""
        sensitive_ports = {
            22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5901: "VNC",
            1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            27017: "MongoDB", 11211: "Memcached", 9200: "Elasticsearch",
            135: "RPC", 139: "NetBIOS", 445: "SMB", 5985: "WinRM",
        }

        for rule in rules:
            if not rule.is_parsed or not rule.is_allow_rule():
                continue

            # Check if rule allows from anywhere (0.0.0.0/0 or ::/0)
            src_is_any = (rule.src_ip in ("0.0.0.0/0", "::/0", "any", "") or
                         (rule.src_ip_obj and rule.src_ip_obj.prefixlen == 0))

            if not src_is_any:
                continue

            # Check destination port
            if rule.dst_port:
                port = rule.dst_port.start
                if port in sensitive_ports:
                    service = sensitive_ports[port]
                    severity = Severity.CRITICAL if port in (22, 3389, 5900, 5901) else Severity.HIGH
                    self.findings.append(Finding(
                        rule_number=rule.rule_number,
                        issue_type=IssueType.OVERLY_PERMISSIVE,
                        severity=severity,
                        title=f"Rule {rule.rule_number} allows {service} from ANY source",
                        description=(
                            f"Rule {rule.rule_number} permits {service} (port {port}) "
                            f"from 0.0.0.0/0 (entire Internet). This exposes {service} "
                            f"to brute-force attacks and unauthorized access."
                        ),
                        recommendation=(
                            f"Restrict source to specific admin networks (e.g., 10.0.0.0/24, "
                            f"192.168.1.0/24) or use a VPN/bastion host for access."
                        ),
                    ))

            # Check for protocol ALL with allow
            if rule.protocol == Protocol.ALL and rule.action == Action.ACCEPT:
                self.findings.append(Finding(
                    rule_number=rule.rule_number,
                    issue_type=IssueType.OVERLY_PERMISSIVE,
                    severity=Severity.HIGH,
                    title=f"Rule {rule.rule_number} allows ALL protocols from {rule.src_ip}",
                    description=(
                        f"Rule {rule.rule_number} permits ALL IP protocols (TCP, UDP, ICMP, etc.) "
                        f"from {rule.src_ip}. This is excessively broad."
                    ),
                    recommendation="Restrict to specific protocols (tcp/udp/icmp) as needed.",
                ))

    def _detect_suspicious_rules(self, rules: List[FirewallRule]):
        """Detect suspicious or risky rule patterns"""
        for rule in rules:
            if not rule.is_parsed:
                continue

            # Allow with no source/dest restriction and no port restriction
            if (rule.action == Action.ACCEPT and
                rule.src_ip in ("0.0.0.0/0", "::/0", "any", "") and
                rule.dst_ip in ("0.0.0.0/0", "::/0", "any", "") and
                rule.dst_port is None and rule.src_port is None):
                self.findings.append(Finding(
                    rule_number=rule.rule_number,
                    issue_type=IssueType.SUSPICIOUS,
                    severity=Severity.CRITICAL,
                    title=f"Rule {rule.rule_number} allows ALL traffic from ANYWHERE",
                    description=(
                        f"Rule {rule.rule_number} is a catch-all ACCEPT with no restrictions. "
                        f"This effectively disables the firewall."
                    ),
                    recommendation="Remove this rule or add specific match criteria immediately.",
                ))

            # LOG rules that might fill disk
            if rule.action == Action.LOG and rule.dst_port is None:
                self.findings.append(Finding(
                    rule_number=rule.rule_number,
                    issue_type=IssueType.SUSPICIOUS,
                    severity=Severity.MEDIUM,
                    title=f"Rule {rule.rule_number} logs all traffic (no port filter)",
                    description=(
                        f"Rule {rule.rule_number} logs every packet without port filtering. "
                        f"This can fill disk space rapidly under load."
                    ),
                    recommendation="Add port/protocol filters to LOG rules or use rate limiting.",
                ))

    def _detect_unused_rules(self, rules: List[FirewallRule]):
        """Detect rules that might never match (after a catch-all deny)"""
        # Find catch-all deny rules
        catch_all_deny_idx = None
        for i, rule in enumerate(rules):
            if (rule.is_parsed and rule.is_deny_rule() and
                rule.src_ip in ("0.0.0.0/0", "::/0", "any", "") and
                rule.dst_ip in ("0.0.0.0/0", "::/0", "any", "") and
                rule.dst_port is None):
                catch_all_deny_idx = i
                break

        if catch_all_deny_idx is not None:
            for i in range(catch_all_deny_idx + 1, len(rules)):
                rule = rules[i]
                if rule.is_parsed:
                    self.findings.append(Finding(
                        rule_number=rule.rule_number,
                        issue_type=IssueType.UNUSED,
                        severity=Severity.LOW,
                        title=f"Rule {rule.rule_number} appears after catch-all deny",
                        description=(
                            f"Rule {rule.rule_number} comes after a catch-all DENY rule "
                            f"(Rule {rules[catch_all_deny_idx].rule_number}). It will never be reached."
                        ),
                        recommendation="Remove unreachable rules or move them before the catch-all deny.",
                        related_rules=[rules[catch_all_deny_idx].rule_number]
                    ))

    # Helper methods

    def _rule_covers(self, earlier: FirewallRule, later: FirewallRule) -> bool:
        """Check if earlier rule completely covers later rule's match criteria"""
        # Action must be same or earlier is catch-all
        if earlier.action != later.action and earlier.action != Action.ACCEPT:
            return False

        # Protocol: earlier must be ALL or match later
        if earlier.protocol != Protocol.ALL and earlier.protocol != later.protocol:
            return False

        # Source IP: earlier must be superset of later
        if not self._ip_covers(earlier.src_ip_obj, later.src_ip_obj):
            return False

        # Destination IP
        if not self._ip_covers(earlier.dst_ip_obj, later.dst_ip_obj):
            return False

        # Ports: earlier must cover later's ports
        if later.dst_port and earlier.dst_port:
            if not earlier.dst_port.overlaps(later.dst_port):
                return False
        elif later.dst_port and not earlier.dst_port:
            # earlier has no port restriction = covers all
            pass
        elif not later.dst_port and earlier.dst_port:
            # later has no port restriction, earlier does = not covered
            return False

        return True

    def _rules_equivalent(self, r1: FirewallRule, r2: FirewallRule) -> bool:
        """Check if two rules have identical match criteria"""
        return (r1.action == r2.action and
                r1.protocol == r2.protocol and
                r1.src_ip == r2.src_ip and
                r1.dst_ip == r2.dst_ip and
                self._ports_equal(r1.src_port, r2.src_port) and
                self._ports_equal(r1.dst_port, r2.dst_port) and
                r1.in_interface == r2.in_interface and
                r1.out_interface == r2.out_interface)

    def _rules_overlap(self, r1: FirewallRule, r2: FirewallRule) -> bool:
        """Check if two rules have overlapping match criteria"""
        # Protocol overlap
        if r1.protocol != Protocol.ALL and r2.protocol != Protocol.ALL and r1.protocol != r2.protocol:
            return False

        # IP overlap
        if not self._ips_overlap(r1.src_ip_obj, r2.src_ip_obj):
            return False
        if not self._ips_overlap(r1.dst_ip_obj, r2.dst_ip_obj):
            return False

        # Port overlap
        if r1.dst_port and r2.dst_port and not r1.dst_port.overlaps(r2.dst_port):
            return False

        return True

    def _ip_covers(self, net1: Optional[object], net2: Optional[object]) -> bool:
        """Check if net1 covers net2 (net1 is superset of net2)"""
        if net1 is None or net2 is None:
            return True
        try:
            return net1.supernet_of(net2) or net1 == net2
        except AttributeError:
            return str(net1) == str(net2)

    def _ips_overlap(self, net1: Optional[object], net2: Optional[object]) -> bool:
        """Check if two IP networks overlap"""
        if net1 is None or net2 is None:
            return True
        try:
            return net1.overlaps(net2)
        except AttributeError:
            return str(net1) == str(net2)

    def _ports_equal(self, p1: Optional[PortRange], p2: Optional[PortRange]) -> bool:
        if p1 is None and p2 is None:
            return True
        if p1 is None or p2 is None:
            return False
        return p1.start == p2.start and p1.end == p2.end


class PolicyChecker:
    """Checks firewall rules against organization policy"""

    def __init__(self, policy: OrganizationPolicy):
        self.policy = policy
        self.findings: List[Finding] = []

    def check(self, rules: List[FirewallRule]) -> List[Finding]:
        """Check all rules against policy"""
        self.findings = []

        for rule in rules:
            if not rule.is_parsed:
                continue

            self._check_rule(rule)

        return self.findings

    def _check_rule(self, rule: FirewallRule):
        """Check a single rule against policy"""
        # Only check ACCEPT rules for policy violations (DENY rules are generally safe)
        if not rule.is_allow_rule():
            return

        # Check prohibited ports
        if rule.dst_port:
            port = rule.dst_port.start
            if self.policy.is_port_prohibited(port):
                self.findings.append(Finding(
                    rule_number=rule.rule_number,
                    issue_type=IssueType.PROHIBITED_PORT,
                    severity=Severity.CRITICAL,
                    title=f"Rule {rule.rule_number} opens prohibited port {port}",
                    description=(
                        f"Organization policy prohibits port {port} ({rule.get_service_name()}) "
                        f"from being open. Rule {rule.rule_number} allows it."
                    ),
                    recommendation=f"Close port {port} or request policy exception with justification.",
                ))

        # Check banned sources
        if self.policy.is_source_banned(rule.src_ip):
            self.findings.append(Finding(
                rule_number=rule.rule_number,
                issue_type=IssueType.BANNED_SOURCE,
                severity=Severity.CRITICAL,
                title=f"Rule {rule.rule_number} allows traffic from banned source {rule.src_ip}",
                description=(
                    f"Source {rule.src_ip} is in the organization's banned sources list. "
                    f"Rule {rule.rule_number} permits traffic from it."
                ),
                recommendation="Remove this rule or change source to allowed network.",
            ))

        # Check service-specific policies
        if rule.dst_port:
            port = rule.dst_port.start
            proto = rule.protocol if rule.protocol != Protocol.ALL else Protocol.TCP
            service_policy = self.policy.get_service(port, proto)

            if service_policy:
                # Check if source is allowed for this service
                if not service_policy.is_source_allowed(rule.src_ip):
                    self.findings.append(Finding(
                        rule_number=rule.rule_number,
                        issue_type=IssueType.POLICY_VIOLATION,
                        severity=Severity.HIGH,
                        title=f"Rule {rule.rule_number} violates {service_policy.name} policy",
                        description=(
                            f"Policy allows {service_policy.name} (port {port}) only from: "
                            f"{', '.join(service_policy.allowed_sources) or 'internal networks'}. "
                            f"Rule {rule.rule_number} allows from {rule.src_ip}."
                        ),
                        recommendation=(
                            f"Restrict source to allowed networks: "
                            f"{', '.join(service_policy.allowed_sources)}"
                        ),
                    ))

                # Check admin access requirement
                if service_policy.requires_admin_access:
                    is_admin = service_policy.is_admin_network(rule.src_ip)
                    if not is_admin:
                        self.findings.append(Finding(
                            rule_number=rule.rule_number,
                            issue_type=IssueType.MISSING_ADMIN_RESTRICTION,
                            severity=Severity.HIGH,
                            title=f"Rule {rule.rule_number}: {service_policy.name} requires admin network",
                            description=(
                                f"Policy requires {service_policy.name} access only from admin networks: "
                                f"{', '.join(service_policy.admin_networks)}. "
                                f"Rule {rule.rule_number} allows from {rule.src_ip}."
                            ),
                            recommendation=(
                                f"Restrict source to admin networks: "
                                f"{', '.join(service_policy.admin_networks)}"
                            ),
                        ))

        # Check for missing logging on sensitive rules
        if (self.policy.require_logging and rule.is_allow_rule() and rule.dst_port):
            port = rule.dst_port.start
            sensitive = {22, 23, 3389, 5900, 5901, 1433, 3306, 5432}
            if port in sensitive:
                # Check if there's a corresponding LOG rule before this
                has_log = False  # Simplified - would need rule order context
                if not has_log:
                    self.findings.append(Finding(
                        rule_number=rule.rule_number,
                        issue_type=IssueType.MISSING_LOGGING,
                        severity=Severity.MEDIUM,
                        title=f"Rule {rule.rule_number}: Sensitive service {rule.get_service_name()} should be logged",
                        description=(
                            f"Policy requires logging for sensitive services. "
                            f"Rule {rule.rule_number} allows {rule.get_service_name()} without logging."
                        ),
                        recommendation="Add a LOG rule before this rule for audit trail.",
                    ))


def calculate_compliance_score(rules: List[FirewallRule],
                               anomaly_findings: List[Finding],
                               policy_findings: List[Finding]) -> Tuple[int, dict]:
    """Calculate compliance score (0-100)"""
    if not rules:
        return 100, {"total_rules": 0, "issues": 0, "breakdown": {}}

    total_rules = len([r for r in rules if r.is_parsed])
    if total_rules == 0:
        return 100, {"total_rules": 0, "issues": 0, "breakdown": {}}

    # Weight by severity
    severity_weights = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 5,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }

    total_penalty = 0
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for finding in anomaly_findings + policy_findings:
        weight = severity_weights.get(finding.severity, 0)
        total_penalty += weight
        breakdown[finding.severity.value] += 1

    # Smooth score: 100 when there are no findings, falling gradually as the
    # severity-weighted penalty grows relative to the size of the rule base.
    # (The old linear formula hit 0% for almost any real-world configuration.)
    #   penalty == 0                    -> 100
    #   penalty == 5 * total_rules      -> 50
    #   penalty == 20 * total_rules     -> ~17
    score = int(round(100 / (1 + total_penalty / (total_rules * 5.0))))
    score = max(0, min(100, score))

    return score, {
        "total_rules": total_rules,
        "issues": len(anomaly_findings) + len(policy_findings),
        "breakdown": breakdown,
        "anomaly_count": len(anomaly_findings),
        "policy_violation_count": len(policy_findings),
    }


def rule_number_sort_key(rule_num):
    """Sort key for rule numbers (handles non-sequential)"""
    return rule_num