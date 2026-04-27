import os
import collections
from tree_sitter import Language, Parser, QueryCursor
import tree_sitter_python as tspy
import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

class KnowledgeGraph:
    def __init__(self, root_path):
        self.root_path = os.path.abspath(root_path)
        self.nodes = {}  
        self.edges = collections.defaultdict(list) 
        self.module_to_path = self._map_internal_boundaries()

        # ── Initialize Universal Parsers ──
        self.parsers = {
            'python': self._setup_parser(tspy.language()),
            'java': self._setup_parser(tsjava.language()),
            'javascript': self._setup_parser(tsjs.language()),
            'typescript': self._setup_parser(tsts.language_typescript()),
            'tsx': self._setup_parser(tsts.language_tsx())
        }

       # ── Universal Import Queries ──
        self.queries = {
            'python': Language(tspy.language()).query("""
                (import_statement name: (_) @import)
                (import_from_statement module_name: (_) @import)
            """), 
            'java': Language(tsjava.language()).query("""
                (import_declaration (scoped_identifier) @import)
            """),
            'javascript': Language(tsjs.language()).query("""
                (import_statement source: (string) @import)
            """),
            'typescript': Language(tsts.language_typescript()).query("""
                (import_statement source: (string) @import)
            """),
            'tsx': Language(tsts.language_tsx()).query("""
                (import_statement source: (string) @import)
            """)
        }

    def _setup_parser(self, lang_payload):
        """Initializes the parser using the new tree-sitter v0.22+ API"""
        # 1. Create the Language object
        lang = Language(lang_payload)
        # 2. Pass the language directly into the Parser constructor
        parser = Parser(lang) 
        return parser 

    def _map_internal_boundaries(self):
        """Phase I: Boundary Delineation"""
        mapping = {}
        valid_exts = {'.py', '.java', '.js', '.jsx', '.ts', '.tsx'}
        for root, _, files in os.walk(self.root_path):
            if any(skip in root for skip in ['node_modules', '.git', '__pycache__', 'dist']):
                continue
                
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in valid_exts:
                    abs_file_path = os.path.abspath(os.path.join(root, f))
                    rel_path = os.path.relpath(abs_file_path, self.root_path)
                    
                    # Store both module syntax (auth.service) and exact filenames (auth/service)
                    module_name = rel_path.replace(os.sep, '.').rsplit('.', 1)[0]
                    exact_name = rel_path.rsplit('.', 1)[0]
                    
                    mapping[module_name] = abs_file_path
                    mapping[exact_name] = abs_file_path
        return mapping

    def analyze_file(self, file_path):
        """Phase II: The Universal Orchestrator"""
        ext = os.path.splitext(file_path)[1].lower().replace('.', '')
        # Map .ts to typescript, .js to javascript, etc.
        lang_map = {'py': 'python', 'java': 'java', 'js': 'javascript', 'jsx': 'javascript', 'ts': 'typescript', 'tsx': 'tsx'}
        
        lang_key = lang_map.get(ext)
        if not lang_key: return

        # Read the file
        try:
            with open(file_path, 'rb') as f:
                code = f.read()
        except Exception:
            return

        # 1. Register the Node
        file_id = file_path 
        basename = os.path.basename(file_path)

        if file_id not in self.nodes:
            self.nodes[file_id] = {"path": file_path, "label": basename, "type": f"{ext.upper()}_FILE", "is_entry": False, "in_degree": 0}

        # 2. Parse the AST
        parser = self.parsers[lang_key]
        tree = parser.parse(code)
        # 3. Query the AST for Imports
        query = self.queries[lang_key]
        
        # NEW: Wrap the query in a QueryCursor (required in v0.22+)
        query_cursor = QueryCursor(query)
        captures = query_cursor.captures(tree.root_node)

        # NEW: Handle the API return type change (List vs Dict)
        if isinstance(captures, dict):
            # v0.22+ returns a Dictionary { "capture_name": [Node, Node] }
            nodes_to_process = [node for nodes_list in captures.values() for node in nodes_list]
        else:
            # v0.21 returns a List of tuples [(Node, "capture_name")]
            nodes_to_process = [node for node, _ in captures]

        for node in nodes_to_process:
            # Extract the raw text of the import (e.g., 'neuroscan.crawler' or './components/App')
            raw_import = code[node.start_byte:node.end_byte].decode('utf8').strip("'\"")
            
            # Clean up JS/TS relative imports (e.g., './utils' -> 'utils')
            clean_import = raw_import.replace('./', '').replace('../', '')

            self._process_universal_import(file_id, clean_import)

    def _process_universal_import(self, source_id, mod_name):
        """Phase III: Universal Edge Creation"""
        # Does this imported module exist in our project boundary?
        if mod_name in self.module_to_path:
            target_id = self.module_to_path[mod_name]
            
            if target_id not in self.edges[source_id]:
                self.edges[source_id].append(target_id)
                
                # Pre-register target node
                if target_id not in self.nodes:
                    self.nodes[target_id] = {
                        "path": target_id, 
                        "label": os.path.basename(target_id),
                        "type": "FILE", 
                        "is_entry": False, 
                        "in_degree": 0
                    }
                self.nodes[target_id]["in_degree"] += 1