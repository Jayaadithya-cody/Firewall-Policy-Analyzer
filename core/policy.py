"""
Organization Policy Model
Defines the security policy that firewall rules should comply with.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import ipaddress
import yaml
from core.rule import Protocol, PortRange, Action


class PolicyType(Enum):
    """Predefined organization types"""
    COLLEGE = "college"
    CORPORATE = "corporate"
    BANKING = "banking"
    CUSTOM = "custom"


def _net(value):
    """Parse an IP address or CIDR into a network ('0.0.0.0/0', '10.0.0.5', '10.0.0.0/24')."""
    return ipaddress.ip_network(str(value).strip(), strict=False)


def _inside(value, containers) -> bool:
    """True if `value` (IP or CIDR) lies completely inside one of the `containers` CIDRs."""
    n = _net(value)
    for c in containers:
        c = _net(c)
        if n.version == c.version and n.subnet_of(c):
            return True
    return False


def _overlaps(value, others) -> bool:
    """True if `value` (IP or CIDR) overlaps any of the CIDRs in `others`."""
    n = _net(value)
    for o in others:
        o = _net(o)
        if n.version == o.version and n.overlaps(o):
            return True
    return False


@dataclass
class ServicePolicy:
    """Policy for a specific service"""
    name: str
    protocol: Protocol
    port: int
    allowed_sources: List[str] = field(default_factory=list)  # CIDR ranges
    denied_sources: List[str] = field(default_factory=list)
    allowed_destinations: List[str] = field(default_factory=list)
    denied_destinations: List[str] = field(default_factory=list)
    requires_admin_access: bool = False
    admin_networks: List[str] = field(default_factory=list)
    description: str = ""

    def is_source_allowed(self, ip: str) -> bool:
        """Check if source IP is allowed for this service"""
        try:
            # Check denied first
            if _inside(ip, self.denied_sources):
                return False
            # If no allowed sources specified, allow all (unless denied)
            if not self.allowed_sources:
                return True
            # The rule's source must lie completely inside an allowed network
            return _inside(ip, self.allowed_sources)
        except ValueError:
            return False

    def is_destination_allowed(self, ip: str) -> bool:
        """Check if destination IP is allowed"""
        try:
            if _inside(ip, self.denied_destinations):
                return False
            if not self.allowed_destinations:
                return True
            if _inside(ip, self.allowed_destinations):
                return True
            return False
        except ValueError:
            return False

    def is_admin_network(self, ip: str) -> bool:
        """Check if IP is from admin network"""
        try:
            return _inside(ip, self.admin_networks)
        except ValueError:
            return False


@dataclass
class NetworkZone:
    """Network zone definition"""
    name: str
    cidr: str
    description: str = ""
    zone_type: str = "internal"  # internal, dmz, external, admin, restricted

    def contains(self, ip: str) -> bool:
        try:
            return _inside(ip, [self.cidr])
        except ValueError:
            return False


@dataclass
class OrganizationPolicy:
    """
    Complete organization security policy.
    Defines what traffic should be allowed/denied based on organization type.
    """
    name: str
    policy_type: PolicyType = PolicyType.CUSTOM
    description: str = ""

    # Network zones
    zones: List[NetworkZone] = field(default_factory=list)

    # Service policies
    services: List[ServicePolicy] = field(default_factory=list)

    # Global rules
    default_deny_inbound: bool = True
    default_deny_outbound: bool = False
    allow_established: bool = True
    allow_icmp: bool = True

    # Restricted items
    prohibited_ports: List[int] = field(default_factory=list)  # Ports that should never be open
    restricted_protocols: List[Protocol] = field(default_factory=list)
    banned_sources: List[str] = field(default_factory=list)  # Known bad IPs/networks

    # Compliance requirements
    require_logging: bool = True
    require_stateful: bool = True
    max_rules_warning: int = 100

    def get_service(self, port: int, protocol: Protocol) -> Optional[ServicePolicy]:
        """Find service policy by port and protocol"""
        for svc in self.services:
            if svc.port == port and (svc.protocol == protocol or svc.protocol == Protocol.ALL):
                return svc
        return None

    def get_service_by_name(self, name: str) -> Optional[ServicePolicy]:
        """Find service policy by name"""
        for svc in self.services:
            if svc.name.lower() == name.lower():
                return svc
        return None

    def is_port_prohibited(self, port: int) -> bool:
        """Check if port is globally prohibited"""
        return port in self.prohibited_ports

    def is_source_banned(self, ip: str) -> bool:
        """Check if source IP is in banned list"""
        try:
            # A range the policy itself uses (zones, admin networks, allowed service sources)
            # is the organization's own network and must not be treated as "banned".
            own = [z.cidr for z in self.zones]
            for svc in self.services:
                own.extend(svc.allowed_sources)
                own.extend(svc.admin_networks)
            own = [o for o in own if o and o not in ("any", "*")]
            banned = [b for b in self.banned_sources
                      if not any(_net(b).version == _net(o).version and _net(b).overlaps(_net(o))
                                 and _net(o).prefixlen > 0 for o in own)]
            return _inside(ip, banned)
        except ValueError:
            return False

    def get_zone(self, ip: str) -> Optional[NetworkZone]:
        """Get zone for an IP address"""
        for zone in self.zones:
            if zone.contains(ip):
                return zone
        return None

    def to_yaml(self) -> str:
        """Serialize to YAML"""
        data = {
            'name': self.name,
            'policy_type': self.policy_type.value,
            'description': self.description,
            'default_deny_inbound': self.default_deny_inbound,
            'default_deny_outbound': self.default_deny_outbound,
            'allow_established': self.allow_established,
            'allow_icmp': self.allow_icmp,
            'prohibited_ports': self.prohibited_ports,
            'restricted_protocols': [p.value for p in self.restricted_protocols],
            'banned_sources': self.banned_sources,
            'require_logging': self.require_logging,
            'require_stateful': self.require_stateful,
            'max_rules_warning': self.max_rules_warning,
            'zones': [
                {
                    'name': z.name,
                    'cidr': z.cidr,
                    'description': z.description,
                    'zone_type': z.zone_type,
                } for z in self.zones
            ],
            'services': [
                {
                    'name': s.name,
                    'protocol': s.protocol.value,
                    'port': s.port,
                    'allowed_sources': s.allowed_sources,
                    'denied_sources': s.denied_sources,
                    'allowed_destinations': s.allowed_destinations,
                    'denied_destinations': s.denied_destinations,
                    'requires_admin_access': s.requires_admin_access,
                    'admin_networks': s.admin_networks,
                    'description': s.description,
                } for s in self.services
            ],
        }
        return yaml.dump(data, sort_keys=False)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> 'OrganizationPolicy':
        """Deserialize from YAML"""
        data = yaml.safe_load(yaml_str)
        policy = cls(
            name=data.get('name', 'Custom Policy'),
            policy_type=PolicyType(data.get('policy_type', 'custom')),
            description=data.get('description', ''),
            default_deny_inbound=data.get('default_deny_inbound', True),
            default_deny_outbound=data.get('default_deny_outbound', False),
            allow_established=data.get('allow_established', True),
            allow_icmp=data.get('allow_icmp', True),
            prohibited_ports=data.get('prohibited_ports', []),
            restricted_protocols=[Protocol(p) for p in data.get('restricted_protocols', [])],
            banned_sources=data.get('banned_sources', []),
            require_logging=data.get('require_logging', True),
            require_stateful=data.get('require_stateful', True),
            max_rules_warning=data.get('max_rules_warning', 100),
        )

        # Load zones
        for z_data in data.get('zones', []):
            policy.zones.append(NetworkZone(
                name=z_data['name'],
                cidr=z_data['cidr'],
                description=z_data.get('description', ''),
                zone_type=z_data.get('zone_type', 'internal'),
            ))

        # Load services
        for s_data in data.get('services', []):
            policy.services.append(ServicePolicy(
                name=s_data['name'],
                protocol=Protocol(s_data['protocol']),
                port=s_data['port'],
                allowed_sources=s_data.get('allowed_sources', []),
                denied_sources=s_data.get('denied_sources', []),
                allowed_destinations=s_data.get('allowed_destinations', []),
                denied_destinations=s_data.get('denied_destinations', []),
                requires_admin_access=s_data.get('requires_admin_access', False),
                admin_networks=s_data.get('admin_networks', []),
                description=s_data.get('description', ''),
            ))

        return policy


def create_sample_policies() -> Dict[str, OrganizationPolicy]:
    """Create sample organization policies"""
    policies = {}

    # College Policy
    college = OrganizationPolicy(
        name="College/University Network",
        policy_type=PolicyType.COLLEGE,
        description="Typical college network with student, faculty, and admin segments",
        default_deny_inbound=True,
        default_deny_outbound=False,
        prohibited_ports=[23, 135, 139, 445, 1433, 3389],  # Telnet, RPC, NetBIOS, SMB, MSSQL, RDP
        banned_sources=["0.0.0.0/8", "127.0.0.0/8"],  # Bogon networks
    )
    college.zones = [
        NetworkZone("Admin Network", "10.0.0.0/24", "Administrative staff", "admin"),
        NetworkZone("Faculty Network", "10.0.1.0/24", "Faculty members", "internal"),
        NetworkZone("Student Network", "10.0.10.0/23", "Student dorms/labs", "internal"),
        NetworkZone("Server DMZ", "10.0.100.0/24", "Public-facing servers", "dmz"),
        NetworkZone("Guest WiFi", "10.0.200.0/24", "Guest wireless", "restricted"),
    ]
    college.services = [
        ServicePolicy("SSH", Protocol.TCP, 22,
                      allowed_sources=["10.0.0.0/24"],  # Admin only
                      requires_admin_access=True,
                      admin_networks=["10.0.0.0/24"],
                      description="Admin SSH access only"),
        ServicePolicy("HTTP", Protocol.TCP, 80,
                      allowed_sources=["0.0.0.0/0"],
                      allowed_destinations=["10.0.100.0/24"],
                      description="Web servers in DMZ"),
        ServicePolicy("HTTPS", Protocol.TCP, 443,
                      allowed_sources=["0.0.0.0/0"],
                      allowed_destinations=["10.0.100.0/24"],
                      description="Secure web servers in DMZ"),
        ServicePolicy("DNS", Protocol.UDP, 53,
                      allowed_sources=["10.0.0.0/16"],
                      description="Internal DNS"),
        ServicePolicy("DHCP", Protocol.UDP, 67,
                      allowed_sources=["10.0.10.0/23", "10.0.200.0/24"],
                      description="Student and guest DHCP"),
        ServicePolicy("NTP", Protocol.UDP, 123,
                      allowed_sources=["10.0.0.0/16"],
                      description="Time synchronization"),
    ]
    policies['college'] = college

    # Corporate Policy
    corporate = OrganizationPolicy(
        name="Corporate Enterprise",
        policy_type=PolicyType.CORPORATE,
        description="Standard corporate network with strict access controls",
        default_deny_inbound=True,
        default_deny_outbound=True,
        prohibited_ports=[23, 135, 139, 445, 1433, 3389, 5900, 5901],  # Add VNC
        banned_sources=["0.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],  # RFC1918 inbound blocked
        require_logging=True,
        require_stateful=True,
    )
    corporate.zones = [
        NetworkZone("Management", "10.10.0.0/24", "Network management", "admin"),
        NetworkZone("Servers", "10.10.10.0/24", "Application servers", "internal"),
        NetworkZone("Databases", "10.10.20.0/24", "Database servers", "restricted"),
        NetworkZone("Employee LAN", "10.10.100.0/22", "Employee workstations", "internal"),
        NetworkZone("DMZ", "10.10.200.0/24", "Public services", "dmz"),
    ]
    corporate.services = [
        ServicePolicy("SSH", Protocol.TCP, 22,
                      allowed_sources=["10.10.0.0/24"],
                      requires_admin_access=True,
                      admin_networks=["10.10.0.0/24"],
                      description="Management network only"),
        ServicePolicy("HTTPS", Protocol.TCP, 443,
                      allowed_sources=["0.0.0.0/0"],
                      allowed_destinations=["10.10.200.0/24"],
                      description="Public web services"),
        ServicePolicy("SMTP", Protocol.TCP, 25,
                      allowed_sources=["10.10.10.0/24"],
                      allowed_destinations=["10.10.200.0/24"],
                      description="Mail relay only"),
        ServicePolicy("DNS", Protocol.UDP, 53,
                      allowed_sources=["10.10.0.0/16"],
                      description="Internal DNS"),
        ServicePolicy("LDAP", Protocol.TCP, 389,
                      allowed_sources=["10.10.0.0/16"],
                      description="Directory services"),
        ServicePolicy("HTTPS-Internal", Protocol.TCP, 8443,
                      allowed_sources=["10.10.0.0/16"],
                      allowed_destinations=["10.10.10.0/24"],
                      description="Internal admin consoles"),
    ]
    policies['corporate'] = corporate

    # Banking Policy (strictest)
    banking = OrganizationPolicy(
        name="Banking/Financial",
        policy_type=PolicyType.BANKING,
        description="Financial institution with maximum security requirements",
        default_deny_inbound=True,
        default_deny_outbound=True,
        prohibited_ports=[21, 23, 25, 53, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5901, 8080],
        banned_sources=["0.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"],
        require_logging=True,
        require_stateful=True,
        max_rules_warning=50,
    )
    banking.zones = [
        NetworkZone("Security Operations", "10.20.0.0/24", "SOC and security team", "admin"),
        NetworkZone("Core Banking", "10.20.10.0/24", "Core banking systems", "restricted"),
        NetworkZone("Database", "10.20.20.0/24", "Financial databases", "restricted"),
        NetworkZone("Internal Apps", "10.20.100.0/24", "Internal applications", "internal"),
        NetworkZone("DMZ", "10.20.200.0/24", "Public banking portal", "dmz"),
    ]
    banking.services = [
        ServicePolicy("SSH", Protocol.TCP, 22,
                      allowed_sources=["10.20.0.0/24"],
                      requires_admin_access=True,
                      admin_networks=["10.20.0.0/24"],
                      description="SOC jump host only"),
        ServicePolicy("HTTPS", Protocol.TCP, 443,
                      allowed_sources=["0.0.0.0/0"],
                      allowed_destinations=["10.20.200.0/24"],
                      description="Customer portal only"),
        ServicePolicy("TLS-Admin", Protocol.TCP, 8443,
                      allowed_sources=["10.20.0.0/24"],
                      allowed_destinations=["10.20.100.0/24"],
                      description="Admin console - SOC only"),
        ServicePolicy("Database", Protocol.TCP, 1521,
                      allowed_sources=["10.20.10.0/24"],
                      allowed_destinations=["10.20.20.0/24"],
                      description="App to DB only"),
    ]
    policies['banking'] = banking

    return policies