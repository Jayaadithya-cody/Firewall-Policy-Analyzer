"""
Iptables Rule Parser
Parses iptables-save or iptables command output into structured FirewallRule objects.
"""
import re
from typing import List, Optional
from core.rule import FirewallRule, Action, Protocol, PortRange


class IptablesParser:
    """Parses iptables rules from text input"""

    # Common port aliases
    PORT_ALIASES = {
        'ssh': 22, 'telnet': 23, 'smtp': 25, 'domain': 53, 'dns': 53,
        'http': 80, 'pop3': 110, 'imap': 143, 'https': 443,
        'smtps': 465, 'submission': 587, 'imaps': 993, 'pop3s': 995,
        'mysql': 3306, 'rdp': 3389, 'postgresql': 5432, 'http-alt': 8080,
    }

    def __init__(self):
        self.errors: List[str] = []
        self.rule_counter = 0

    def parse(self, input_text: str) -> List[FirewallRule]:
        """Parse iptables rules from text"""
        self.errors = []
        self.rule_counter = 0
        rules = []

        lines = input_text.strip().split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            rule = self._parse_line(line, line_num)
            if rule:
                rules.append(rule)

        return rules

    def _parse_line(self, line: str, line_num: int) -> Optional[FirewallRule]:
        """Parse a single iptables rule line"""
        # Handle both iptables-save format and command format
        # iptables-save: -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT
        # Command: iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT

        # Remove leading 'iptables' if present
        if line.startswith('iptables '):
            line = line[9:].strip()

        rule = FirewallRule(raw_rule=line, line_number=line_num)
        self.rule_counter += 1
        rule.rule_number = self.rule_counter

        try:
            # Parse tokens
            tokens = self._tokenize(line)
            self._parse_tokens(rule, tokens)
            rule.is_parsed = True
        except Exception as e:
            rule.is_parsed = False
            rule.parse_error = str(e)
            self.errors.append(f"Line {line_num}: {e}")

        return rule

    def _tokenize(self, line: str) -> List[str]:
        """Split line into tokens, respecting quoted strings"""
        # Simple tokenizer for iptables arguments
        tokens = []
        current = ""
        in_quotes = False
        quote_char = None

        i = 0
        while i < len(line):
            char = line[i]
            if char in ('"', "'") and (i == 0 or line[i-1] != '\\'):
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
                current += char
            elif char.isspace() and not in_quotes:
                if current:
                    tokens.append(current)
                    current = ""
            else:
                current += char
            i += 1

        if current:
            tokens.append(current)

        return tokens

    def _parse_tokens(self, rule: FirewallRule, tokens: List[str]):
        """Parse tokens into rule attributes"""
        i = 0
        while i < len(tokens):
            token = tokens[i]

            if token == '-A' or token == '--append':
                if i + 1 < len(tokens):
                    rule.chain = tokens[i + 1].upper()
                    i += 2
                else:
                    i += 1

            elif token == '-p' or token == '--protocol':
                if i + 1 < len(tokens):
                    proto_str = tokens[i + 1].lower()
                    rule.protocol = self._parse_protocol(proto_str)
                    i += 2
                else:
                    i += 1

            elif token == '-s' or token == '--source' or token == '--src':
                if i + 1 < len(tokens):
                    rule.src_ip = tokens[i + 1]
                    i += 2
                else:
                    i += 1

            elif token == '-d' or token == '--destination' or token == '--dst':
                if i + 1 < len(tokens):
                    rule.dst_ip = tokens[i + 1]
                    i += 2
                else:
                    i += 1

            elif token == '-j' or token == '--jump':
                if i + 1 < len(tokens):
                    action_str = tokens[i + 1].upper()
                    rule.action = self._parse_action(action_str)
                    i += 2
                else:
                    i += 1

            elif token == '--dport' or token == '--destination-port':
                if i + 1 < len(tokens):
                    rule.dst_port = self._parse_port(tokens[i + 1])
                    i += 2
                else:
                    i += 1

            elif token == '--sport' or token == '--source-port':
                if i + 1 < len(tokens):
                    rule.src_port = self._parse_port(tokens[i + 1])
                    i += 2
                else:
                    i += 1

            elif token == '-i' or token == '--in-interface':
                if i + 1 < len(tokens):
                    rule.in_interface = tokens[i + 1]
                    i += 2
                else:
                    i += 1

            elif token == '-o' or token == '--out-interface':
                if i + 1 < len(tokens):
                    rule.out_interface = tokens[i + 1]
                    i += 2
                else:
                    i += 1

            elif token == '-m' or token == '--match':
                if i + 1 < len(tokens):
                    match_type = tokens[i + 1]
                    if match_type == 'state' and i + 2 < len(tokens):
                        # Handle --state NEW,ESTABLISHED
                        state_token = tokens[i + 2]
                        if state_token.startswith('--state'):
                            if '=' in state_token:
                                states = state_token.split('=')[1].split(',')
                            elif i + 3 < len(tokens):
                                states = tokens[i + 3].split(',')
                            else:
                                states = []
                            rule.state = [s.strip().upper() for s in states]
                            i += 3
                        else:
                            i += 2
                    elif match_type == 'tcp' and i + 2 < len(tokens):
                        # Handle --tcp-flags
                        if tokens[i + 2] == '--tcp-flags' and i + 3 < len(tokens):
                            rule.flags = tokens[i + 3].split(',')
                            i += 4
                        else:
                            i += 2
                    else:
                        i += 2
                else:
                    i += 1

            elif token == '--icmp-type':
                if i + 1 < len(tokens):
                    rule.icmp_type = tokens[i + 1]
                    i += 2
                else:
                    i += 1

            elif token == '-m' and i + 1 < len(tokens) and tokens[i + 1] == 'comment':
                if i + 2 < len(tokens) and tokens[i + 2] == '--comment':
                    if i + 3 < len(tokens):
                        # Comment may have spaces, reconstruct
                        comment_parts = []
                        j = i + 3
                        while j < len(tokens):
                            comment_parts.append(tokens[j])
                            j += 1
                        rule.comment = ' '.join(comment_parts).strip('"')
                        i = j
                    else:
                        i += 3
                else:
                    i += 1

            else:
                i += 1

        # Post-process IP objects
        rule.__post_init__()

    def _parse_protocol(self, proto_str: str) -> Protocol:
        """Parse protocol string to enum"""
        proto_str = proto_str.lower()
        if proto_str in ('tcp', '6'):
            return Protocol.TCP
        elif proto_str in ('udp', '17'):
            return Protocol.UDP
        elif proto_str in ('icmp', '1'):
            return Protocol.ICMP
        elif proto_str in ('all', '0', 'ip'):
            return Protocol.ALL
        return Protocol.UNKNOWN

    def _parse_action(self, action_str: str) -> Action:
        """Parse action string to enum"""
        action_str = action_str.upper()
        if action_str == 'ACCEPT':
            return Action.ACCEPT
        elif action_str == 'DROP':
            return Action.DROP
        elif action_str == 'REJECT':
            return Action.REJECT
        elif action_str == 'LOG':
            return Action.LOG
        return Action.UNKNOWN

    def _parse_port(self, port_str: str) -> Optional[PortRange]:
        """Parse port specification (single port, range, or alias)"""
        port_str = port_str.strip()

        # Handle port aliases
        if port_str.lower() in self.PORT_ALIASES:
            port = self.PORT_ALIASES[port_str.lower()]
            return PortRange(port, port)

        # Handle range (e.g., "80:443" or "80-443")
        if ':' in port_str:
            parts = port_str.split(':')
            try:
                start = int(parts[0])
                end = int(parts[1])
                return PortRange(min(start, end), max(start, end))
            except ValueError:
                pass
        elif '-' in port_str and not port_str.startswith('-'):
            parts = port_str.split('-')
            try:
                start = int(parts[0])
                end = int(parts[1])
                return PortRange(min(start, end), max(start, end))
            except ValueError:
                pass

        # Single port
        try:
            port = int(port_str)
            if 0 <= port <= 65535:
                return PortRange(port, port)
        except ValueError:
            pass

        return None


def parse_iptables(input_text: str) -> List[FirewallRule]:
    """Convenience function to parse iptables rules"""
    parser = IptablesParser()
    return parser.parse(input_text)