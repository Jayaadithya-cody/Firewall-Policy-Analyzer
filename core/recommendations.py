"""
Rule Recommendation Engine
Generates specific, actionable recommendations for detected findings.
"""
from typing import Optional, List, Tuple
import ipaddress
from core.rule import FirewallRule, Action, Protocol, PortRange
from core.policy import OrganizationPolicy, ServicePolicy
from core.detector import Finding, IssueType, Severity


class RecommendationEngine:
    """Generates specific fixes for firewall rule findings"""

    def __init__(self, policy: Optional[OrganizationPolicy] = None):
        self.policy = policy

    def generate_recommendation(self, finding: Finding, rule: FirewallRule,
                                all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """
        Generate recommendation and suggested fix for a finding.

        Returns:
            Tuple of (recommendation_text, suggested_rule_or_None)
            suggested_rule_or_None is a FirewallRule with the fix applied,
            or None if automatic fix cannot be determined safely.
        """
        handler_map = {
            IssueType.SHADOWED: self._fix_shadowed,
            IssueType.REDUNDANT: self._fix_redundant,
            IssueType.CONFLICTING: self._fix_conflicting,
            IssueType.OVERLY_PERMISSIVE: self._fix_overly_permissive,
            IssueType.SUSPICIOUS: self._fix_suspicious,
            IssueType.UNUSED: self._fix_unused,
            IssueType.PROHIBITED_PORT: self._fix_prohibited_port,
            IssueType.BANNED_SOURCE: self._fix_banned_source,
            IssueType.POLICY_VIOLATION: self._fix_policy_violation,
            IssueType.MISSING_ADMIN_RESTRICTION: self._fix_missing_admin_restriction,
            IssueType.MISSING_LOGGING: self._fix_missing_logging,
        }

        handler = handler_map.get(finding.issue_type)
        if handler:
            return handler(finding, rule, all_rules)

        return finding.recommendation, None

    def _fix_shadowed(self, finding: Finding, rule: FirewallRule,
                      all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Shadowed rule - recommend removal"""
        rec = (
            f"Rule {rule.rule_number} is completely shadowed by an earlier rule and will never be reached. "
            f"Recommendation: Remove this rule from the configuration."
        )
        # Suggested fix: mark for removal (return None to indicate deletion)
        return rec, None  # None means delete this rule

    def _fix_redundant(self, finding: Finding, rule: FirewallRule,
                       all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Redundant rule - recommend removal"""
        related = finding.related_rules[0] if finding.related_rules else "unknown"
        rec = (
            f"Rule {rule.rule_number} duplicates Rule {related} (same match criteria and action). "
            f"Recommendation: Remove Rule {rule.rule_number} to reduce configuration complexity."
        )
        return rec, None  # None means delete this rule

    def _fix_conflicting(self, finding: Finding, rule: FirewallRule,
                         all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Conflicting rules - recommend reordering or narrowing"""
        related = finding.related_rules[0] if finding.related_rules else "unknown"
        earlier_rule = next((r for r in all_rules if r.rule_number == related), None)

        if not earlier_rule:
            return finding.recommendation, None

        # Try to suggest narrowing the later rule
        rec = (
            f"Rule {rule.rule_number} conflicts with Rule {related}. "
            f"Rule {related} ({earlier_rule.action.value}) takes precedence. "
            f"Options: (1) Reorder rules if {rule.action.value} should apply first, "
            f"(2) Narrow Rule {rule.rule_number}'s match criteria to avoid overlap, "
            f"(3) Remove Rule {rule.rule_number} if {earlier_rule.action.value} is desired."
        )

        # Suggest narrowing the source IP if that's the overlap
        if earlier_rule.src_ip != rule.src_ip:
            # Suggest restricting source to non-overlapping range (simplified)
            return rec, None

        return rec, None

    def _fix_overly_permissive(self, finding: Finding, rule: FirewallRule,
                               all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Overly permissive - suggest restricting source"""
        if not rule.dst_port:
            return finding.recommendation, None

        port = rule.dst_port.start
        service = rule.get_service_name()

        # If policy exists and has admin networks, suggest those
        suggested_source = "10.0.0.0/24"  # Default fallback
        if self.policy:
            svc_policy = self.policy.get_service(port, rule.protocol if rule.protocol != Protocol.ALL else Protocol.TCP)
            if svc_policy and svc_policy.admin_networks:
                suggested_source = svc_policy.admin_networks[0]
            elif self.policy.zones:
                admin_zones = [z for z in self.policy.zones if z.zone_type == "admin"]
                if admin_zones:
                    suggested_source = admin_zones[0].cidr

        rec = (
            f"Rule {rule.rule_number} allows {service} (port {port}) from ANY source (0.0.0.0/0). "
            f"This exposes {service} to the entire Internet. "
            f"Recommendation: Restrict source to a trusted admin network such as {suggested_source}."
        )

        # Create suggested rule with restricted source
        suggested_rule = FirewallRule(
            rule_number=rule.rule_number,
            raw_rule="",  # Will be regenerated
            chain=rule.chain,
            action=rule.action,
            protocol=rule.protocol,
            src_ip=suggested_source,
            dst_ip=rule.dst_ip,
            src_port=rule.src_port,
            dst_port=rule.dst_port,
            in_interface=rule.in_interface,
            out_interface=rule.out_interface,
            state=rule.state.copy(),
            flags=rule.flags.copy(),
            icmp_type=rule.icmp_type,
            comment=rule.comment,
            line_number=rule.line_number,
            is_parsed=True,
        )

        return rec, suggested_rule

    def _fix_suspicious(self, finding: Finding, rule: FirewallRule,
                        all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Suspicious rule - usually catch-all allow"""
        if (rule.action == Action.ACCEPT and
            rule.src_ip in ("0.0.0.0/0", "::/0", "any", "") and
            rule.dst_ip in ("0.0.0.0/0", "::/0", "any", "") and
            rule.dst_port is None):
            rec = (
                f"Rule {rule.rule_number} is a catch-all ACCEPT with no restrictions. "
                f"This effectively disables the firewall. "
                f"Recommendation: Remove this rule immediately or add specific match criteria."
            )
            return rec, None  # Delete

        if rule.action == Action.LOG and rule.dst_port is None:
            rec = (
                f"Rule {rule.rule_number} logs all traffic without port filtering. "
                f"This can fill disk space rapidly. "
                f"Recommendation: Add port/protocol filters or use rate limiting."
            )
            return rec, None

        return finding.recommendation, None

    def _fix_unused(self, finding: Finding, rule: FirewallRule,
                    all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Unused rule after catch-all deny"""
        related = finding.related_rules[0] if finding.related_rules else "unknown"
        rec = (
            f"Rule {rule.rule_number} comes after a catch-all DENY (Rule {related}) and will never be reached. "
            f"Recommendation: Remove this unreachable rule or move it before the catch-all deny."
        )
        return rec, None  # Delete

    def _fix_prohibited_port(self, finding: Finding, rule: FirewallRule,
                             all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Prohibited port - recommend closing"""
        port = rule.dst_port.start if rule.dst_port else 0
        rec = (
            f"Organization policy prohibits port {port} ({rule.get_service_name()}). "
            f"Rule {rule.rule_number} opens this port. "
            f"Recommendation: Remove this rule or request a policy exception with justification."
        )
        return rec, None  # Delete

    def _fix_banned_source(self, finding: Finding, rule: FirewallRule,
                           all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Banned source - recommend changing source"""
        rec = (
            f"Rule {rule.rule_number} allows traffic from banned source {rule.src_ip}. "
            f"Recommendation: Change source to an allowed network or remove the rule."
        )
        # Could suggest an allowed network from policy zones
        suggested_source = "10.0.0.0/24"
        if self.policy:
            internal_zones = [z for z in self.policy.zones if z.zone_type == "internal"]
            if internal_zones:
                suggested_source = internal_zones[0].cidr

        suggested_rule = FirewallRule(
            rule_number=rule.rule_number,
            raw_rule="",
            chain=rule.chain,
            action=rule.action,
            protocol=rule.protocol,
            src_ip=suggested_source,
            dst_ip=rule.dst_ip,
            src_port=rule.src_port,
            dst_port=rule.dst_port,
            in_interface=rule.in_interface,
            out_interface=rule.out_interface,
            state=rule.state.copy(),
            flags=rule.flags.copy(),
            icmp_type=rule.icmp_type,
            comment=rule.comment,
            line_number=rule.line_number,
            is_parsed=True,
        )

        return rec, suggested_rule

    def _fix_policy_violation(self, finding: Finding, rule: FirewallRule,
                              all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Service policy violation - restrict to allowed sources"""
        if not self.policy or not rule.dst_port:
            return finding.recommendation, None

        port = rule.dst_port.start
        proto = rule.protocol if rule.protocol != Protocol.ALL else Protocol.TCP
        svc_policy = self.policy.get_service(port, proto)

        if not svc_policy or not svc_policy.allowed_sources:
            return finding.recommendation, None

        # Use first allowed source
        suggested_source = svc_policy.allowed_sources[0]

        rec = (
            f"Policy allows {svc_policy.name} (port {port}) only from: "
            f"{', '.join(svc_policy.allowed_sources)}. "
            f"Rule {rule.rule_number} allows from {rule.src_ip}. "
            f"Recommendation: Restrict source to {suggested_source}."
        )

        suggested_rule = FirewallRule(
            rule_number=rule.rule_number,
            raw_rule="",
            chain=rule.chain,
            action=rule.action,
            protocol=rule.protocol,
            src_ip=suggested_source,
            dst_ip=rule.dst_ip,
            src_port=rule.src_port,
            dst_port=rule.dst_port,
            in_interface=rule.in_interface,
            out_interface=rule.out_interface,
            state=rule.state.copy(),
            flags=rule.flags.copy(),
            icmp_type=rule.icmp_type,
            comment=rule.comment,
            line_number=rule.line_number,
            is_parsed=True,
        )

        return rec, suggested_rule

    def _fix_missing_admin_restriction(self, finding: Finding, rule: FirewallRule,
                                       all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Missing admin restriction - restrict to admin networks"""
        if not self.policy or not rule.dst_port:
            return finding.recommendation, None

        port = rule.dst_port.start
        proto = rule.protocol if rule.protocol != Protocol.ALL else Protocol.TCP
        svc_policy = self.policy.get_service(port, proto)

        if not svc_policy or not svc_policy.admin_networks:
            return finding.recommendation, None

        suggested_source = svc_policy.admin_networks[0]

        rec = (
            f"Policy requires {svc_policy.name} access only from admin networks: "
            f"{', '.join(svc_policy.admin_networks)}. "
            f"Rule {rule.rule_number} allows from {rule.src_ip}. "
            f"Recommendation: Restrict source to {suggested_source}."
        )

        suggested_rule = FirewallRule(
            rule_number=rule.rule_number,
            raw_rule="",
            chain=rule.chain,
            action=rule.action,
            protocol=rule.protocol,
            src_ip=suggested_source,
            dst_ip=rule.dst_ip,
            src_port=rule.src_port,
            dst_port=rule.dst_port,
            in_interface=rule.in_interface,
            out_interface=rule.out_interface,
            state=rule.state.copy(),
            flags=rule.flags.copy(),
            icmp_type=rule.icmp_type,
            comment=rule.comment,
            line_number=rule.line_number,
            is_parsed=True,
        )

        return rec, suggested_rule

    def _fix_missing_logging(self, finding: Finding, rule: FirewallRule,
                             all_rules: List[FirewallRule]) -> Tuple[str, Optional[FirewallRule]]:
        """Missing logging - recommend adding LOG rule"""
        rec = (
            f"Policy requires logging for sensitive service {rule.get_service_name()}. "
            f"Recommendation: Add a LOG rule before Rule {rule.rule_number} for audit trail."
        )
        # Cannot auto-fix this - requires inserting a new rule
        return rec, None


def rule_to_iptables(rule: FirewallRule) -> str:
    """Convert a FirewallRule back to iptables command string"""
    parts = ["-A", rule.chain]

    if rule.protocol != Protocol.ALL and rule.protocol != Protocol.UNKNOWN:
        parts.extend(["-p", rule.protocol.value])

    if rule.src_ip and rule.src_ip not in ("0.0.0.0/0", "::/0", "any", ""):
        parts.extend(["-s", rule.src_ip])

    if rule.dst_ip and rule.dst_ip not in ("0.0.0.0/0", "::/0", "any", ""):
        parts.extend(["-d", rule.dst_ip])

    if rule.dst_port:
        if rule.dst_port.start == rule.dst_port.end:
            parts.extend(["--dport", str(rule.dst_port.start)])
        else:
            parts.extend(["--dport", f"{rule.dst_port.start}:{rule.dst_port.end}"])

    if rule.src_port:
        if rule.src_port.start == rule.src_port.end:
            parts.extend(["--sport", str(rule.src_port.start)])
        else:
            parts.extend(["--sport", f"{rule.src_port.start}:{rule.src_port.end}"])

    if rule.in_interface:
        parts.extend(["-i", rule.in_interface])

    if rule.out_interface:
        parts.extend(["-o", rule.out_interface])

    if rule.state:
        parts.extend(["-m", "state", "--state", ",".join(rule.state)])

    if rule.flags:
        parts.extend(["-m", "tcp", "--tcp-flags", ",".join(rule.flags)])

    if rule.icmp_type:
        parts.extend(["--icmp-type", rule.icmp_type])

    if rule.comment:
        parts.extend(["-m", "comment", "--comment", f'"{rule.comment}"'])

    parts.extend(["-j", rule.action.value])

    return " ".join(parts)