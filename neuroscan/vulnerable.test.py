import os
import subprocess
import pickle
from neuroscan.auditor import audit_file


# --- 1. Hardcoded Secret (High Entropy) ---
# This should trigger the "Hardcoded Secret" rule and show a high entropy score.
AWS_SECRET_KEY = "k3jS92ls02klS92lskL02lsK92lskL02lsK92ls" 

# --- 2. Insecure Eval ---
# This allows a user to run arbitrary code.
user_input = "print('Hacked!')"
eval(user_input)

# --- 3. Command Injection Risk ---
# This talks directly to the OS.
os.system("ls -la")
subprocess.run(["echo", "Danger!"])

# --- 4. Insecure Deserialization ---
# Pickle can be used to run malicious code during loading.
data = b"cos\nsystem\n(S'whoami'\ntR."
pickle.loads(data)

def dummy_route():
    """
    @app.route('/test') 
    This comment won't be caught by AST, 
    but a real decorator will be!
    """
    pass