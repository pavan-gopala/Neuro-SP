import os
import collections
from tree_sitter import Language, Parser

# Language Bindings
import tree_sitter_python as tspython
import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript
import tree_sitter_go as tsgo

class KnowledgeGraph:
    def __init__(self, root_path):
        self.root_path = os.path.abspath(root_path)
        
        # Final graph state
        self.nodes = {}  # {normalized_path: metadata}
        self.edges = collections.defaultdict(list)  # {source_node: [target_nodes]}
        
        # State tracked during pass 1 and resolved in pass 2
        self._raw_imports = collections.defaultdict(list)
        self._api_endpoints = set()
        self._api_calls = collections.defaultdict(list)
        
        # 1. Initialize Tree-sitter Parsers
        self.langs = {
            'python': Language(tspython.language()),
            'java': Language(tsjava.language()),
            'javascript': Language(tsjavascript.language()),
            'typescript': Language(tstypescript.language_typescript()),
            'tsx': Language(tstypescript.language_tsx()),
            'go': Language(tsgo.language())
        }
        
        self.parsers = {lang: Parser(self.langs[lang]) for lang in self.langs}

        # Shared JS/TS Query
        js_ts_query = """
            (import_statement source: (string (string_fragment) @import.name))
            (call_expression function: (identifier) @func arguments: (arguments (string (string_fragment) @import.name)) (#eq? @func "require"))
            (call_expression function: (identifier) @api.call arguments: (arguments (string (string_fragment) @api.route)) (#match? @api.call "^(fetch|axios)$"))
            (member_expression object: (member_expression object: (identifier) @obj property: (property_identifier) @prop (#eq? @obj "process") (#eq? @prop "env")) property: (property_identifier) @env.name)
            (call_expression function: (member_expression property: (property_identifier) @route.method (#match? @route.method "^(get|post|put|delete|patch|all)$")))
        """

        # 2. Pre-compile queries
        self.queries = {
            'python': self.langs['python'].query("""
                (import_statement (dotted_name) @import.module)
                (import_from_statement module_name: (dotted_name) @import.from)
                (call function: (attribute object: (attribute object: (identifier) @obj attribute: (identifier) @attr) attribute: (identifier) @meth) arguments: (argument_list (string (string_content) @env.name)) (#eq? @obj "os") (#eq? @attr "environ") (#eq? @meth "get"))
                (decorator (identifier) @route.name)
                (decorator (call function: (identifier) @route.name))
            """),
            'java': self.langs['java'].query("""
                (import_declaration (scoped_identifier) @import.name)
                (method_invocation object: (identifier) @obj name: (identifier) @meth arguments: (argument_list (string_literal (string_fragment) @env.name)) (#eq? @obj "System") (#eq? @meth "getenv"))
                (marker_annotation name: (identifier) @route.name)
                (annotation name: (identifier) @route.name)
            """),
            'javascript': self.langs['javascript'].query(js_ts_query),
            'typescript': self.langs['typescript'].query(js_ts_query),
            'tsx': self.langs['tsx'].query(js_ts_query),
            'go': self.langs['go'].query("""
                (import_spec path: (interpreted_string_literal) @import.name)
                (call_expression function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @func (#eq? @pkg "os") (#eq? @func "Getenv")) arguments: (argument_list (interpreted_string_literal) @env.name))
                (call_expression function: (selector_expression field: (field_identifier) @route.method (#match? @route.method "^(HandleFunc|GET|POST|PUT|DELETE|PATCH)$")))
            """)
        }

    def _normalize_path(self, file_path):
        """Safely generates a clean Node ID to prevent Ghost Nodes."""
        abs_path = os.path.abspath(file_path)
        rel_path = os.path.relpath(abs_path, self.root_path)
        return rel_path.replace(os.sep, '/')

    def analyze_file(self, file_path, node_id=None):
        """Pass 1: Data Extraction."""
        # Auto-generate the clean ID if cli.py didn't pass it
        if node_id is None:
            node_id = self._normalize_path(file_path)

        ext = file_path.rsplit('.', 1)[-1].lower()
        ext_to_lang = {
            'py': 'python', 'java': 'java', 'js': 'javascript', 
            'ts': 'typescript', 'tsx': 'tsx', 'go': 'go'
        }
        if ext in ext_to_lang:
            # Now it correctly passes all 3 arguments!
            self._parse_with_treesitter(file_path, node_id, ext_to_lang[ext]) 
    def _parse_with_treesitter(self, file_path, node_id, lang_key):
        try:
            with open(file_path, 'rb') as f:
                source_bytes = f.read()
                
            tree = self.parsers[lang_key].parse(source_bytes)
            
            if node_id not in self.nodes:
                self.nodes[node_id] = {
                    "path": node_id, 
                    "type": "FILE", 
                    "lang": lang_key,
                    "is_entry": False, 
                    "in_degree": 0,
                    "out_degree": 0
                }

            query = self.queries[lang_key]
            extracted_captures = []

            # --- UNIVERSAL TREE-SITTER API HANDLER ---
            # Automatically adapts to tree-sitter v0.21, v0.22, and v0.23+
            if hasattr(query, 'captures') and not hasattr(query, 'matches'):
                # Old API (v0.21)
                for ast_node, capture_name in query.captures(tree.root_node):
                    extracted_captures.append((capture_name, ast_node))
            else:
                # Newer APIs (v0.22+ or QueryCursor)
                matches_data = []
                if hasattr(query, 'matches'):
                    matches_data = query.matches(tree.root_node)
                else:
                    # v0.23+ moved execution to a new QueryCursor object
                    from tree_sitter import QueryCursor
                    cursor = QueryCursor(query)
                    matches_data = cursor.matches(tree.root_node)
                
                for match in matches_data:
                    # Match is usually a tuple: (pattern_index, {capture_name: [nodes]})
                    captures_dict = match[1] if isinstance(match, tuple) else match
                    if isinstance(captures_dict, dict):
                        for capture_name, nodes in captures_dict.items():
                            node_list = nodes if isinstance(nodes, list) else [nodes]
                            for ast_node in node_list:
                                extracted_captures.append((capture_name, ast_node))

            # --- PROCESS EXTRACTED DATA ---
            for capture_name, ast_node in extracted_captures:
                if not hasattr(ast_node, 'text') or ast_node.text is None:
                    continue
                    
                text = ast_node.text.decode('utf-8').strip('\'"')
                
                if capture_name.startswith('import'):
                    self._raw_imports[node_id].append(text)
                elif capture_name.startswith('route'):
                    self.nodes[node_id]["is_entry"] = True
                    self.nodes[node_id]["type"] = "ENTRY_POINT"
                elif capture_name == 'env.name':
                    env_id = f"ENV_{text}"
                    if env_id not in self.nodes:
                        self.nodes[env_id] = {"type": "ENV_VAR", "in_degree": 0, "out_degree": 0}
                    self.edges[node_id].append(env_id)
                elif capture_name == 'api.route':
                    self._api_calls[node_id].append(text)

        except Exception as e:
            print(f"Graph Warning - Failed to parse {os.path.basename(file_path)}: {e}")
    def build_relationships(self):
        """Pass 2: Edge Resolution with X-RAY DEBUGGING."""
        all_known_nodes = list(self.nodes.keys())
        
        # X-RAY 1: Did we find ANY imports?
        print("\n[X-RAY] Raw Imports Extracted:")
        for source, imports in self._raw_imports.items():
            if imports:
                print(f"  {source} imports -> {imports}")
        
        edges_created = 0

        for source_node, imports in self._raw_imports.items():
            for imp in imports:
                clean_imp = imp.replace('.', '/')
                
                for target_node in all_known_nodes:
                    if self.nodes[target_node].get("type") != "FILE": continue
                    
                    target_base = target_node.rsplit('.', 1)[0]
                    
                    # X-RAY 2: Show the attempted match for a specific file
                    if "cli.py" in source_node and "crawler" in target_node:
                        print(f"[X-RAY MATCH TRY] Source: {source_node} | Trying to match import '{clean_imp}' with target '{target_base}'")

                    if clean_imp.endswith(target_base) or target_base.endswith(clean_imp):
                        if target_node not in self.edges[source_node]:
                            self.edges[source_node].append(target_node)
                            self.nodes[source_node]["out_degree"] += 1
                            self.nodes[target_node]["in_degree"] += 1
                            edges_created += 1
                            print(f"[SUCCESS] Connected {source_node} -> {target_node}")
                            
        print(f"\n[X-RAY] Total Edges Created: {edges_created}")
    def get_all_paths(self, start_node, target_node, path=None):
        if path is None: path = [start_node]
        if start_node == target_node: return [path]
        if start_node not in self.edges: return []
        
        paths = []
        for neighbor in self.edges[start_node]:
            if neighbor not in path:
                paths.extend(self.get_all_paths(neighbor, target_node, path + [neighbor]))
        return paths
