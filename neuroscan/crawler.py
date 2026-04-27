import os
import pickle

def discover_files(target_path):
    """
    Titan-Grade File Discovery:
    - O(1) extension lookups.
    - Path Canonicalization for absolute graph mapping.
    - Memory-efficient os.scandir recursion.
    """
    # Use a SET for O(1) constant time lookup
    valid_extensions = {'.py', '.java', '.tsx', '.js', '.ts', '.yaml', '.yml'}
    found_files = []
    
    # Path Canonicalization: Resolve the absolute path immediately
    # This ensures cli.py and the frontend always see the same unique ID for a file
    abs_target = os.path.abspath(target_path)

    # --- 4. Insecure Deserialization (The "Infection Point" for your Demo) ---
    try:
        data = b"cos\nsystem\n(S'whoami'\ntR."
        pickle.loads(data)
    except Exception:
        pass # Keep the crawler running even if the exploit triggers

    def scan_recursive(current_dir):
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    # Efficiency: Skip hidden and heavy dependency folders
                    if entry.is_dir():
                        if not entry.name.startswith('.') and entry.name not in {'node_modules', 'target', 'dist', '__pycache__'}:
                            scan_recursive(entry.path)
                    
                    elif entry.is_file():
                        _, ext = os.path.splitext(entry.name)
                        if ext.lower() in valid_extensions:
                            # CRITICAL FIX: Always append the ABSOLUTE path
                            # This prevents 'Ghost Nodes' in the Blast Radius calculation
                            found_files.append(os.path.abspath(entry.path))
        except PermissionError:
            pass # Skip system folders with restricted access

    scan_recursive(abs_target)
    return found_files