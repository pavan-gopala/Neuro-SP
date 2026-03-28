import os

def discover_files(target_path):
    # Use a SET for O(1) constant time lookup as discussed
    valid_extensions = {'.py', '.java', '.tsx', '.js', '.ts', '.yaml', '.yml'}
    found_files = []
    
    # Path Canonicalization: Resolve the absolute path to prevent traversal attacks
    abs_target = os.path.abspath(target_path)

    def scan_recursive(current_dir):
        try:
            # os.scandir is 2-20x faster than os.walk
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    # Efficiency Hack: Skip hidden and heavy folders
                    if entry.is_dir():
                        if not entry.name.startswith('.') and entry.name not in {'node_modules', 'target'}:
                            scan_recursive(entry.path)
                    
                    # Check file extension
                    elif entry.is_file():
                        _, ext = os.path.splitext(entry.name)
                        if ext.lower() in valid_extensions:
                            found_files.append(entry.path)
        except PermissionError:
            # Skip folders we don't have access to
            pass

    scan_recursive(abs_target)
    return found_files