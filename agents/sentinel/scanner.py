import re
import os
from agents.sentinel.validator import TokenValidator

__version__ = "0.1.0"

def neuro_scan(file_path):
    validator = TokenValidator()
    
    patterns = {
        "GitHub Personal Token": r"ghp_[a-zA-Z0-9]{36}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}"
    }

    if not os.path.exists(file_path):
        return f"Error: {file_path} not found."

    with open(file_path, 'r') as f:
        content = f.read() # Read the file once
        
        # Move the loop ABOVE the search
        for label, regex in patterns.items():
            match = re.search(regex, content)
            if match:
                token = match.group()
                if validator.isValid(token):
                    return f"🚨 [NEURAL ALERT] {label} detected in {file_path}! Action: Move to .env immediately."
                
    return "✅ [SAFE] No immediate exposure detected."

def main():
    # For demonstration, we will scan the README.md in the root directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(os.path.dirname(script_dir))
    target_file = os.path.join(root_dir, "README.md")
    
    print(f"--- Neuro-SP Sentinel v{__version__} ---")
    print(f"--- Neuro-SP Sentinel Scan Initiated ---")
    print(f"Target: {target_file}")
    print(neuro_scan(target_file))

# Lab Test: Run this to check your own README
if __name__ == "__main__":
    main()