"""
Firewall Rule Model
Represents a single iptables-style firewall rule with parsed attributes.
"""
from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum
import ipaddress


class Action(Enum):
    """Firewall rule actions"""
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    LOG = "LOG"
    UNKNOWN = "UNKNOWN"


class Protocol(Enum):
    """Network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"
    UNKNOWN = "unknown"


@dataclass
class PortRange:
    """Represents a port or port range"""
    start: int
    end: int

    def __str__(self):
        if self.start == self.end:
            return str(self.start)
        return f"{self.start}-{self.end}"

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end

    def overlaps(self, other: 'PortRange') -> bool:
        return not (self.end < other.start or other.end < self.start)


@dataclass
class FirewallRule:
    """
    Represents a parsed firewall rule.
    Based on iptables rule structure.
    """
    # Rule identification
    rule_number: int = 0
    raw_rule: str = ""

    # Chain information
    chain: str = "INPUT"  # INPUT, OUTPUT, FORWARD, etc.

    # Action
    action: Action = Action.UNKNOWN

    # Protocol
    protocol: Protocol = Protocol.ALL

    # Source
    src_ip: str = "0.0.0.0/0"  # CIDR notation
    src_ip_obj: Optional[ipaddress.IPv4Network] = None

    # Destination
    dst_ip: str = "0.0.0.0/0"
    dst_ip_obj: Optional[ipaddress.IPv4Network] = None

    # Ports
    src_port: Optional[PortRange] = None
    dst_port: Optional[PortRange] = None

    # Interface
    in_interface: str = ""
    out_interface: str = ""

    # State/connection tracking
    state: List[str] = field(default_factory=list)  # NEW, ESTABLISHED, RELATED, INVALID

    # Additional flags
    flags: List[str] = field(default_factory=list)  # SYN, ACK, FIN, etc.
    icmp_type: str = ""

    # Comments
    comment: str = ""

    # Metadata for analysis
    line_number: int = 0
    is_parsed: bool = False
    parse_error: str = ""

    def __post_init__(self):
        """Initialize IP objects after creation"""
        try:
            self.src_ip_obj = ipaddress.ip_network(self.src_ip, strict=False)
        except ValueError:
            self.src_ip_obj = ipaddress.ip_network("0.0.0.0/0", strict=False)

        try:
            self.dst_ip_obj = ipaddress.ip_network(self.dst_ip, strict=False)
        except ValueError:
            self.dst_ip_obj = ipaddress.ip_network("0.0.0.0/0", strict=False)

    def matches_ip(self, ip_str: str, is_source: bool = True) -> bool:
        """Check if an IP matches this rule's source or destination"""
        try:
            ip = ipaddress.ip_address(ip_str)
            network = self.src_ip_obj if is_source else self.dst_ip_obj
            return ip in network
        except ValueError:
            return False

    def matches_port(self, port: int, is_source: bool = True) -> bool:
        """Check if a port matches this rule's source or destination port"""
        port_range = self.src_port if is_source else self.dst_port
        if port_range is None:
            return True  # No port restriction = matches all
        return port_range.contains(port)

    def matches_protocol(self, proto: Protocol) -> bool:
        """Check if protocol matches"""
        return self.protocol == Protocol.ALL or self.protocol == proto

    def is_allow_rule(self) -> bool:
        """Check if this is an allow/accept rule"""
        return self.action == Action.ACCEPT

    def is_deny_rule(self) -> bool:
        """Check if this is a deny/drop/reject rule"""
        return self.action in (Action.DROP, Action.REJECT)

    def get_service_name(self) -> str:
        """Get human-readable service name from destination port"""
        if self.dst_port is None:
            return "any"
        port = self.dst_port.start
        common_ports = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SMTP Submission",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP Alt",
        }
        return common_ports.get(port, f"Port {port}")

    def to_dict(self) -> dict:
        """Convert to dictionary for display/serialization"""
        return {
            "rule_number": self.rule_number,
            "chain": self.chain,
            "action": self.action.value,
            "protocol": self.protocol.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": str(self.src_port) if self.src_port else "any",
            "dst_port": str(self.dst_port) if self.dst_port else "any",
            "in_interface": self.in_interface,
            "out_interface": self.out_interface,
            "state": ",".join(self.state) if self.state else "any",
            "comment": self.comment,
        }

    def __str__(self):
        parts = [f"Rule {self.rule_number}: {self.chain} {self.action.value}"]
        if self.protocol != Protocol.ALL:
            parts.append(f"proto {self.protocol.value}")
        parts.append(f"src {self.src_ip}")
        parts.append(f"dst {self.dst_ip}")
        if self.dst_port:
            parts.append(f"dport {self.dst_port}")
        if self.comment:
            parts.append(f"# {self.comment}")
        return " ".join(parts)