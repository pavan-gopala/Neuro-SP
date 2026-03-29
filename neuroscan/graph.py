import ast
import os
import collections

class KnowledgeGraph:
    def __init__(self, root_path):
        self.root_path = os.path.abspath(root_path)
        self.nodes = {}  # {node_id: metadata}
        self.edges = collections.defaultdict(list)
        self.internal_modules = self._map_internal_boundaries()

    def _map_internal_boundaries(self):
        """Phase I: Boundary Delineation (Python & Java)"""
        boundaries = set()
        for root, _, files in os.walk(self.root_path):
            for f in files:
                if f.endswith(('.py', '.java')):
                    rel_path = os.path.relpath(os.path.join(root, f), self.root_path)
                    module_name = rel_path.replace(os.sep, '.').rsplit('.', 1)[0]
                    boundaries.add(module_name)
        return boundaries

    def analyze_file(self, file_path):
        """Orchestrator for multi-language parsing."""
        if file_path.endswith('.py'):
            self._parse_python_ast(file_path)
        elif file_path.endswith('.java'):
            self._parse_java_stub(file_path)

    def _parse_python_ast(self, file_path):
        """Phase II & III: AST Extraction (Imports, Envs, Entry Points)"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
            
            file_id = os.path.basename(file_path)
            if file_id not in self.nodes:
                self.nodes[file_id] = {"path": file_path, "type": "FILE", "is_entry": False, "in_degree": 0}
            else:
                self.nodes[file_id].update({"path": file_path, "type": "FILE"})
            
            for node in ast.walk(tree):
                # 1. Detect Imports
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    self._process_python_import(file_id, node)
                
                # 2. Detect Entry Points (Decorators like @app.route)
                if isinstance(node, ast.FunctionDef):
                    for dec in node.decorator_list:
                        if (hasattr(dec, 'attr') and dec.attr in ['route', 'get', 'post']) or \
                           (isinstance(dec, ast.Call) and hasattr(dec.func, 'attr') and dec.func.attr in ['route', 'get', 'post']):
                            self.nodes[file_id]["is_entry"] = True
                            self.nodes[file_id]["type"] = "ENTRY_POINT"

                # 3. Detect Env Variables (os.environ.get)
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and node.func.attr == 'get':
                        if hasattr(node.func.value, 'attr') and node.func.value.attr == 'environ':
                            env_name = f"ENV_{node.args[0].value}" if node.args else "UNKNOWN_ENV"
                            self._add_env_node(file_id, env_name)

        except Exception as e:
            print(f"AST Error in {os.path.basename(file_path)}: {e}")

    def _process_python_import(self, source_id, node):
        """Identifies internal dependencies and adds graph edges."""
        mods = []
        if isinstance(node, ast.Import):
            mods = [n.name for n in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods = [node.module] if node.module else []

        for mod in mods:
            if mod in self.internal_modules:
                # Map the module name back to a filename
                target_id = f"{mod.split('.')[-1]}.py"
                if target_id not in self.edges[source_id]:
                    self.edges[source_id].append(target_id)
                    # Pre-register target node to track centrality (in-degree)
                    if target_id not in self.nodes:
                        self.nodes[target_id] = {"type": "FILE", "is_entry": False, "in_degree": 0}
                    self.nodes[target_id]["in_degree"] += 1

    def _add_env_node(self, source_id, env_id):
        if env_id not in self.nodes:
            self.nodes[env_id] = {"type": "ENV_VAR", "in_degree": 0}
        if env_id not in self.edges[source_id]:
            self.edges[source_id].append(env_id)
            self.nodes[env_id]["in_degree"] += 1

    def get_all_paths(self, start_node, target_node, path=None):
        """Phase V: DFS for Qualitative Attack Narratives."""
        if path is None: path = [start_node]
        if start_node == target_node: return [path]
        if start_node not in self.edges: return []
        
        paths = []
        for neighbor in self.edges[start_node]:
            if neighbor not in path:
                new_paths = self.get_all_paths(neighbor, target_node, path + [neighbor])
                for p in new_paths:
                    paths.append(p)
        return paths

    def _parse_java_stub(self, file_path):
        file_id = os.path.basename(file_path)
        self.nodes[file_id] = {"path": file_path, "type": "JAVA_FILE", "in_degree": 0}