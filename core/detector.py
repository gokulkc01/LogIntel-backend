from core.patterns import PATTERNS, mask_value
from core.schemas import Finding


def detect(lines: list[tuple[int, str]], mask: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    # Track IPs globally across all lines to avoid repeating same IP
    seen_ip_values: set[str] = set()

    for line_num, text in lines:
        for pattern, risk, type_name in PATTERNS:
            match = pattern.findall(text)
            for m in match: 
                raw_value = m if isinstance(m, str) else m[0]

                # Deduplicate IPs by value across the whole file
                if type_name == "ip_address":
                    if raw_value in seen_ip_values:
                        continue
                    seen_ip_values.add(raw_value)

                key = (line_num, type_name)
                if key in seen:
                    continue
                seen.add(key)

                value = mask_value(raw_value) if mask else raw_value
                if type_name in ("password", "connection_string"):
                    value = "[REDACTED]"

                findings.append(Finding(
                    type=type_name,
                    risk=risk,
                    line=line_num,
                    value=value
                ))

    return sorted(findings, key=lambda f: f.line)