"""
Rule Validation
Validates user-edited firewall rules before applying changes.
"""
from typing import Optional, Tuple, List
import ipaddress
from core.rule import FirewallRule, Action, Protocol, PortRange


class ValidationError(Exception):
    """Raised when rule validation fails"""
    pass


def validate_ip_cidr(ip_str: str, field_name: str) -> ipaddress.IPv4Network:
    """Validate and parse an IP CIDR notation"""
    ip_str = ip_str.strip()
    if not ip_str or ip_str.lower() in ("any", "0.0.0.0/0", "::/0"):
        return ipaddress.ip_network("0.0.0.0/0", strict=False)

    try:
        return ipaddress.ip_network(ip_str, strict=False)
    except ValueError as e:
        raise ValidationError(f"Invalid {field_name}: '{ip_str}'. Use CIDR notation (e.g., 192.168.1.0/24) or 'any'.")


def validate_port(port_str: str, field_name: str) -> Optional[PortRange]:
    """Validate and parse a port or port range"""
    port_str = port_str.strip()
    if not port_str or port_str.lower() in ("any", ""):
        return None

    # Handle port aliases
    port_aliases = {
        'ssh': 22, 'telnet': 23, 'smtp': 25, 'domain': 53, 'dns': 53,
        'http': 80, 'pop3': 110, 'imap': 143, 'https': 443,
        'smtps': 465, 'submission': 587, 'imaps': 993, 'pop3s': 995,
        'mysql': 3306, 'rdp': 3389, 'postgresql': 5432, 'http-alt': 8080,
    }

    if port_str.lower() in port_aliases:
        port = port_aliases[port_str.lower()]
        return PortRange(port, port)

    # Handle range (e.g., "80:443" or "80-443")
    if ':' in port_str:
        parts = port_str.split(':')
        try:
            start = int(parts[0])
            end = int(parts[1])
            if not (0 <= start <= 65535 and 0 <= end <= 65535):
                raise ValidationError(f"Invalid {field_name}: ports must be between 0 and 65535.")
            return PortRange(min(start, end), max(start, end))
        except ValueError:
            raise ValidationError(f"Invalid {field_name}: '{port_str}'. Use format 'start:end' (e.g., 80:443).")
    elif '-' in port_str and not port_str.startswith('-'):
        parts = port_str.split('-')
        try:
            start = int(parts[0])
            end = int(parts[1])
            if not (0 <= start <= 65535 and 0 <= end <= 65535):
                raise ValidationError(f"Invalid {field_name}: ports must be between 0 and 65535.")
            return PortRange(min(start, end), max(start, end))
        except ValueError:
            raise ValidationError(f"Invalid {field_name}: '{port_str}'. Use format 'start-end' (e.g., 80-443).")

    # Single port
    try:
        port = int(port_str)
        if not (0 <= port <= 65535):
            raise ValidationError(f"Invalid {field_name}: port must be between 0 and 65535.")
        return PortRange(port, port)
    except ValueError:
        raise ValidationError(f"Invalid {field_name}: '{port_str}'. Enter a port number (1-65535) or 'any'.")


def validate_protocol(proto_str: str) -> Protocol:
    """Validate and parse protocol"""
    from core.rule import Protocol
    proto_str = proto_str.strip().lower()
    if proto_str in ('tcp', '6'):
        return Protocol.TCP
    elif proto_str in ('udp', '17'):
        return Protocol.UDP
    elif proto_str in ('icmp', '1'):
        return Protocol.ICMP
    elif proto_str in ('all', '0', 'ip', ''):
        return Protocol.ALL
    else:
        raise ValidationError(f"Invalid protocol: '{proto_str}'. Use tcp, udp, icmp, or all.")


def validate_action(action_str: str) -> Action:
    """Validate and parse action"""
    from core.rule import Action
    action_str = action_str.strip().upper()
    if action_str in ('ACCEPT', 'DROP', 'REJECT', 'LOG'):
        return Action(action_str)
    else:
        raise ValidationError(f"Invalid action: '{action_str}'. Use ACCEPT, DROP, REJECT, or LOG.")


def validate_chain(chain_str: str) -> str:
    """Validate chain name"""
    chain_str = chain_str.strip().upper()
    valid_chains = ['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING']
    if chain_str not in valid_chains:
        raise ValidationError(f"Invalid chain: '{chain_str}'. Use INPUT, OUTPUT, FORWARD, PREROUTING, or POSTROUTING.")
    return chain_str


def validate_interfaces(in_iface: str, out_iface: str) -> Tuple[str, str]:
    """Validate interface names (basic validation)"""
    # Interfaces can be empty or standard names like eth0, ens33, etc.
    # Basic validation: alphanumeric, dots, dashes, underscores
    import re
    iface_pattern = re.compile(r'^[a-zA-Z0-9._-]*$')

    if in_iface and not iface_pattern.match(in_iface.strip()):
        raise ValidationError(f"Invalid input interface: '{in_iface}'. Use alphanumeric characters, dots, dashes, or underscores.")

    if out_iface and not iface_pattern.match(out_iface.strip()):
        raise ValidationError(f"Invalid output interface: '{out_iface}'. Use alphanumeric characters, dots, dashes, or underscores.")

    return in_iface.strip(), out_iface.strip()


def validate_state(state_str: str) -> List[str]:
    """Validate connection state"""
    if not state_str or state_str.strip().lower() in ("any", ""):
        return []

    valid_states = {'NEW', 'ESTABLISHED', 'RELATED', 'INVALID', 'UNTRACKED'}
    states = [s.strip().upper() for s in state_str.split(',') if s.strip()]

    for state in states:
        if state not in valid_states:
            raise ValidationError(f"Invalid state: '{state}'. Valid states: NEW, ESTABLISHED, RELATED, INVALID, UNTRACKED")

    return states


def validate_flags(flags_str: str) -> List[str]:
    """Validate TCP flags"""
    if not flags_str or flags_str.strip().lower() in ("any", ""):
        return []

    valid_flags = {'SYN', 'ACK', 'FIN', 'RST', 'URG', 'PSH', 'ALL', 'NONE'}
    flags = [f.strip().upper() for f in flags_str.split(',') if f.strip()]

    for flag in flags:
        if flag not in valid_flags:
            raise ValidationError(f"Invalid TCP flag: '{flag}'. Valid flags: SYN, ACK, FIN, RST, URG, PSH, ALL, NONE")

    return flags


def validate_icmp_type(icmp_str: str) -> str:
    """Validate ICMP type"""
    if not icmp_str or icmp_str.strip().lower() in ("any", ""):
        return ""
    return icmp_str.strip()


def validate_comment(comment: str) -> str:
    """Validate comment (basic sanitization)"""
    if not comment:
        return ""
    # Remove any problematic characters
    comment = comment.strip().strip('"').strip("'")
    if len(comment) > 256:
        raise ValidationError("Comment too long (max 256 characters)")
    return comment


def validate_rule_fields(
    chain: str,
    protocol: str,
    src_ip: str,
    dst_ip: str,
    src_port: str,
    dst_port: str,
    action: str,
    in_interface: str = "",
    out_interface: str = "",
    state: str = "",
    flags: str = "",
    icmp_type: str = "",
    comment: str = ""
) -> FirewallRule:
    """
    Validate all rule fields and return a FirewallRule object.
    Raises ValidationError if any field is invalid.
    """
    # Validate each field
    validated_chain = validate_chain(chain)
    validated_protocol = validate_protocol(protocol)
    validated_src_ip = validate_ip_cidr(src_ip, "source IP")
    validated_dst_ip = validate_ip_cidr(dst_ip, "destination IP")
    validated_src_port = validate_port(src_port, "source port")
    validated_dst_port = validate_port(dst_port, "destination port")
    validated_action = validate_action(action)
    validated_in_iface, validated_out_iface = validate_interfaces(in_interface, out_interface)
    validated_state = validate_state(state)
    validated_flags = validate_flags(flags)
    validated_icmp_type = validate_icmp_type(icmp_type)
    validated_comment = validate_comment(comment)

    # Protocol-specific validation
    if validated_protocol == Protocol.ICMP and validated_dst_port:
        raise ValidationError("ICMP protocol cannot have destination port")

    if validated_protocol in (Protocol.TCP, Protocol.UDP) and not validated_dst_port and validated_action == Action.ACCEPT:
        # Warning: accept rule without port - but not an error
        pass

    # Create the rule
    rule = FirewallRule(
        chain=validated_chain,
        action=validated_action,
        protocol=validated_protocol,
        src_ip=str(validated_src_ip),
        dst_ip=str(validated_dst_ip),
        src_port=validated_src_port,
        dst_port=validated_dst_port,
        in_interface=validated_in_iface,
        out_interface=validated_out_iface,
        state=validated_state,
        flags=validated_flags,
        icmp_type=validated_icmp_type,
        comment=validated_comment,
        is_parsed=True,
    )

    return rule


def apply_rule_edit(original_rule: FirewallRule, edited_fields: dict) -> FirewallRule:
    """
    Apply edited fields to a rule, keeping unedited fields from the original.
    Returns a new FirewallRule with the changes applied.
    """
    # Build fields dict with original values
    fields = {
        'chain': original_rule.chain,
        'protocol': original_rule.protocol.value,
        'src_ip': original_rule.src_ip,
        'dst_ip': original_rule.dst_ip,
        'src_port': str(original_rule.src_port) if original_rule.src_port else "any",
        'dst_port': str(original_rule.dst_port) if original_rule.dst_port else "any",
        'action': original_rule.action.value,
        'in_interface': original_rule.in_interface,
        'out_interface': original_rule.out_interface,
        'state': ','.join(original_rule.state) if original_rule.state else "",
        'flags': ','.join(original_rule.flags) if original_rule.flags else "",
        'icmp_type': original_rule.icmp_type,
        'comment': original_rule.comment,
    }

    # Override with edited values
    for key, value in edited_fields.items():
        if key in fields:
            fields[key] = value

    # Validate and create new rule
    new_rule = validate_rule_fields(**fields)
    new_rule.rule_number = original_rule.rule_number
    new_rule.line_number = original_rule.line_number

    return new_rule