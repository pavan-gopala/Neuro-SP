import re
import math

def calculate_entropy(text):
    """Calculates the Shannon entropy to identify likely random secrets."""
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = text.count(x) / len(text)
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def audit_file(file_path):
    rules = {
    # 1. OWASP A02 – Cryptographic Failures | CWE-798
    "Hardcoded Secret": (
        r"(password|api_key|secret|token|auth|passwd|pwd)\s*=\s*['\"].+['\"]",
        "CRITICAL"
    ),

    # 2. OWASP A03 – Injection | CWE-95
    "Insecure Eval": (
        r"eval\s*\(.+\)",
        "CRITICAL"
    ),

    # 3. OWASP A03 – Injection | CWE-78
    "Command Injection Risk": (
        r"(os\.system|subprocess\.run|subprocess\.call|subprocess\.Popen|os\.popen)\s*\(.+\)",
        "CRITICAL"
    ),

    # 4. OWASP A08 – Software & Data Integrity Failures | CWE-502
    "Insecure Deserialization": (
        r"pickle\.loads\s*\(.+\)",
        "CRITICAL"
    ),

    # 5. OWASP A03 – Injection | CWE-89
    "SQL Injection Risk": (
        r"(execute|raw)\s*\(\s*[\"']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP).+(%s|%d|\{|\+|format)",
        "CRITICAL"
    ),

    # 6. OWASP A02 – Cryptographic Failures | CWE-327
    "Weak Cryptography": (
        r"(hashlib\.(md5|sha1)|MD5\(|SHA1\()",
        "CRITICAL"
    ),

    # 7. OWASP A01 – Broken Access Control | CWE-22
    "Path Traversal Risk": (
        r"(open|os\.path\.join|os\.path\.abspath)\s*\(.*\+.*(request\.|input\(|argv)",
        "CRITICAL"
    ),

    # 8. OWASP A05 – Security Misconfiguration | CWE-94
    "Dynamic Code Execution": (
        r"\bexec\s*\(.+\)",
        "CRITICAL"
    ),

    # 9. OWASP A02 – Cryptographic Failures | CWE-338
    "Insecure Randomness": (
        r"random\.(random|randint|choice|randrange)\s*\(",
        "CRITICAL"
    ),

    # 10. OWASP A05 – Security Misconfiguration | CWE-215
    "Debug Mode Enabled": (
        r"(app\.run\(.*debug\s*=\s*True|DEBUG\s*=\s*True)",
        "CRITICAL"
    ),
    } 
    # Mapped Object Structure
    report = {
        "file_path": file_path,
        "is_config": file_path.endswith(('.yaml', '.yml', '.env', '.json', '.conf')),
        "total_issues": 0,
        "findings": []
    }

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                clean_line = line.strip()

                # Skip empty lines and comments
                if not clean_line or clean_line.startswith('#'):
                    continue

                for issue_name, (pattern, severity) in rules.items():
                    if re.search(pattern, clean_line, re.IGNORECASE):

                        # Calculate entropy only for potential secrets
                        entropy = 0
                        if issue_name == "Hardcoded Secret":
                            value_match = re.search(r"['\"](.+)['\"]", clean_line)
                            if value_match:
                                entropy = calculate_entropy(value_match.group(1))

                        report["findings"].append({
                            "type": issue_name,
                            "severity": severity,
                            "line_number": line_no,
                            "entropy_score": entropy,
                            "snippet": clean_line[:50] + "..." if len(clean_line) > 50 else clean_line
                        })

        # Set total issue count after scanning
        report["total_issues"] = len(report["findings"])

    except FileNotFoundError:
        report["error"] = f"File not found: {file_path}"
    except UnicodeDecodeError:
        report["error"] = f"Unable to decode file (non UTF-8): {file_path}"
    except Exception as e:
        report["error"] = str(e)

    return report