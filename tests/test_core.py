"""Test core modules"""
import sys
sys.path.insert(0, 'c:/Users/jayaa/OneDrive/Desktop/claude_folder/firewall_analyzer')

from core.parser import parse_iptables
from core.policy import create_sample_policies, OrganizationPolicy
from core.detector import AnomalyDetector, PolicyChecker, calculate_compliance_score


def test_parser():
    """Test iptables parser"""
    sample = """
-A INPUT -p tcp -s 0.0.0.0/0 --dport 22 -j ACCEPT
-A INPUT -p tcp -s 10.0.0.0/24 --dport 80 -j ACCEPT
-A INPUT -p udp -s 192.168.1.0/24 --dport 53 -j ACCEPT
-A INPUT -j DROP
"""
    rules = parse_iptables(sample)
    print(f"Parsed {len(rules)} rules")
    for r in rules:
        print(f"  Rule {r.rule_number}: {r}")
        print(f"    Parsed: {r.is_parsed}, Action: {r.action}, Proto: {r.protocol}")
        print(f"    Src: {r.src_ip}, Dst: {r.dst_ip}, Dport: {r.dst_port}")
    assert len(rules) == 4
    assert rules[0].action.name == "ACCEPT"
    assert rules[3].action.name == "DROP"
    print("[OK] Parser test passed")


def test_policy_loading():
    """Test policy loading"""
    policies = create_sample_policies()
    print(f"Loaded {len(policies)} sample policies")
    for key, policy in policies.items():
        print(f"  {key}: {policy.name} ({len(policy.services)} services, {len(policy.zones)} zones)")
    assert 'college' in policies
    assert 'corporate' in policies
    assert 'banking' in policies
    print("[OK] Policy loading test passed")


def test_yaml_roundtrip():
    """Test YAML serialization"""
    policies = create_sample_policies()
    college = policies['college']
    yaml_str = college.to_yaml()
    print("YAML output (first 500 chars):")
    print(yaml_str[:500])
    restored = OrganizationPolicy.from_yaml(yaml_str)
    assert restored.name == college.name
    assert len(restored.services) == len(college.services)
    print("[OK] YAML roundtrip test passed")


def test_anomaly_detection():
    """Test anomaly detector"""
    sample = """
-A INPUT -p tcp -s 0.0.0.0/0 --dport 22 -j ACCEPT
-A INPUT -p tcp -s 0.0.0.0/0 -d 10.0.100.0/24 --dport 80 -j ACCEPT
-A INPUT -p tcp -s 0.0.0.0/0 -d 10.0.100.0/24 --dport 80 -j ACCEPT
-A INPUT -p tcp -s 10.0.0.0/24 --dport 22 -j ACCEPT
-A INPUT -j DROP
-A INPUT -p tcp -s 192.168.1.0/24 --dport 8080 -j ACCEPT
"""
    rules = parse_iptables(sample)
    detector = AnomalyDetector()
    findings = detector.analyze(rules)
    print(f"Found {len(findings)} anomalies:")
    for f in findings:
        print(f"  Rule {f.rule_number}: [{f.severity.value}] {f.title}")
        print(f"    {f.description}")
    assert len(findings) > 0
    print("[OK] Anomaly detection test passed")


def test_policy_checking():
    """Test policy checker"""
    sample = """
-A INPUT -p tcp -s 0.0.0.0/0 --dport 22 -j ACCEPT
-A INPUT -p tcp -s 0.0.0.0/0 --dport 23 -j ACCEPT
-A INPUT -p tcp -s 10.0.0.0/24 --dport 22 -j ACCEPT
-A INPUT -p tcp -s 0.0.0.0/0 -d 10.0.100.0/24 --dport 443 -j ACCEPT
"""
    rules = parse_iptables(sample)
    policies = create_sample_policies()
    college = policies['college']

    checker = PolicyChecker(college)
    findings = checker.check(rules)
    print(f"Found {len(findings)} policy violations:")
    for f in findings:
        print(f"  Rule {f.rule_number}: [{f.severity.value}] {f.title}")
    assert len(findings) > 0
    print("[OK] Policy checking test passed")


def test_compliance_score():
    """Test compliance scoring"""
    sample = """
-A INPUT -p tcp -s 0.0.0.0/0 --dport 22 -j ACCEPT
-A INPUT -p tcp -s 0.0.0.0/0 --dport 23 -j ACCEPT
-A INPUT -j DROP
"""
    rules = parse_iptables(sample)
    policies = create_sample_policies()
    college = policies['college']

    detector = AnomalyDetector()
    anomaly_findings = detector.analyze(rules)

    checker = PolicyChecker(college)
    policy_findings = checker.check(rules)

    score, details = calculate_compliance_score(rules, anomaly_findings, policy_findings)
    print(f"Compliance Score: {score}%")
    print(f"Details: {details}")
    assert 0 <= score <= 100
    print("[OK] Compliance scoring test passed")


if __name__ == "__main__":
    print("=" * 50)
    print("Running Core Module Tests")
    print("=" * 50)

    test_parser()
    print()
    test_policy_loading()
    print()
    test_yaml_roundtrip()
    print()
    test_anomaly_detection()
    print()
    test_policy_checking()
    print()
    test_compliance_score()
    print()
    print("=" * 50)
    print("All tests passed!")
    print("=" * 50)

def test_cidr_sources_match_policy():
    """A rule whose source is a CIDR inside an allowed network must not be a violation."""
    from core.policy import ServicePolicy
    from core.rule import Protocol
    svc = ServicePolicy(name="HTTP", port=80, protocol=Protocol.TCP, allowed_sources=["0.0.0.0/0"])
    assert svc.is_source_allowed("0.0.0.0/0")
    ssh = ServicePolicy(name="SSH", port=22, protocol=Protocol.TCP, allowed_sources=["10.0.0.0/24"])
    assert ssh.is_source_allowed("10.0.0.0/25")
    assert not ssh.is_source_allowed("0.0.0.0/0")


def test_score_is_graded_not_zero():
    from core.detector import calculate_compliance_score
    rules = parse_iptables(open("data/samples/sample_rules.txt", encoding="utf-8").read())
    policy = create_sample_policies()["college"]
    a = AnomalyDetector().analyze(rules)
    p = PolicyChecker(policy).check(rules)
    score, _ = calculate_compliance_score(rules, a, p)
    assert 0 < score < 100
    assert calculate_compliance_score(rules, [], [])[0] == 100


def test_pdf_report_builds():
    from core.report import generate_pdf_report, build_optimized_ruleset
    text = open("data/samples/sample_rules.txt", encoding="utf-8").read()
    rules = parse_iptables(text)
    policy = create_sample_policies()["college"]
    a = AnomalyDetector().analyze(rules)
    p = PolicyChecker(policy).check(rules)
    score, details = calculate_compliance_score(rules, a, p)
    pdf = generate_pdf_report(rules, a, p, score, details, policy, text)
    assert pdf.startswith(b"%PDF") and len(pdf) > 5000
    lines, _ = build_optimized_ruleset(rules, a, p, policy)
    assert lines[-1] == "-A INPUT -j DROP"
