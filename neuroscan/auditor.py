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
    # Expanded Rule Set
    rules = {
        "Hardcoded Secret": r"(password|api_key|secret|token|auth)\s*=\s*['\"].+['\"]",
        "Insecure Eval": r"eval\(.*\)",
        "Command Injection Risk": r"(os\.system|subprocess\.run|subprocess\.call)\(.*\)",
        "Insecure Deserialization": r"pickle\.loads\(.*\)"
    }
    
    # Mapped Object Structure
    report = {
        "file_path": file_path,
        "is_config": file_path.endswith(('.yaml', '.yml', '.env', '.json', '.conf')),
        "findings": []
    }

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                clean_line = line.strip()
                for issue_name, pattern in rules.items():
                    if re.search(pattern, clean_line, re.IGNORECASE):
                        
                        # Calculate entropy if it's a potential secret
                        entropy = 0
                        if issue_name == "Hardcoded Secret":
                            # Extract the value inside quotes
                            value_match = re.search(r"['\"](.+)['\"]", clean_line)
                            if value_match:
                                entropy = calculate_entropy(value_match.group(1))

                        report["findings"].append({
                            "type": issue_name,
                            "line_number": line_no,
                            "entropy_score": entropy,
                            "snippet": clean_line[:50] + "..." if len(clean_line) > 50 else clean_line
                        })
    except Exception as e:
        report["error"] = str(e)
        
    return report