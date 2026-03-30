import argparse
import json
import webbrowser
import threading
import os
import sys
import socket
import uvicorn
import time
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.responses import FileResponse

# Internal Neuro-SP Modules
from neuroscan.crawler import discover_files
from neuroscan.auditor import audit_file
from neuroscan.graph import KnowledgeGraph

def get_free_port():
    """PRD Requirement: Dynamic Port Allocation to avoid 'Address in use' errors."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def get_ui_path():
    """Points to the compiled React production bundle."""
    if hasattr(sys, '_MEIPASS'):
        # For the final .exe / binary version
        return os.path.join(sys._MEIPASS, 'ui')
    
    # Development: Point directly to your neuro-frontend build output
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, 'neuro-frontend', 'dist')

def start_titan_server(port):
    """
    PRD Section 4: High-Performance ASGI Server using Starlette.
    Serves the UI and the Knowledge Graph asynchronously.
    """
    async def get_report(request):
        return FileResponse('graph_report.json')

    # Define routes: Serve static files (UI) and the dynamic report
    routes = [
        Route('/graph_report.json', get_report),
        Mount('/', app=StaticFiles(directory=get_ui_path(), html=True), name="ui")
    ]
    
    app = Starlette(debug=False, routes=routes)
    
    print(f"🚀 Neuro-SP Titan Engine active at: http://localhost:{port}")
    webbrowser.open(f"http://localhost:{port}")
    
    # Run Uvicorn (ASGI) - PRD Section 4 mandate
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="error")

def main():
    parser = argparse.ArgumentParser(description="Neuro-SP Security Scanner")
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--target", type=str, default=".")
    args = parser.parse_args()

    if not args.analyze:
        print("[!] Use --analyze to start the engine.")
        return

    target_root = os.path.abspath(args.target)
    print(f"\n[+] Initializing Neuro-SP [TITAN MODE] on target: {target_root} ...")
    
    kg = KnowledgeGraph(target_root)
    files = discover_files(target_root)
    
    # DEBUG: Verify crawler finds the frontend
    tsx_count = sum(1 for f in files if f.endswith('.tsx'))
    print(f"[DEBUG] Crawler found {len(files)} total files ({tsx_count} are .tsx files)")
    
    all_findings = {}
    
    # ---------------------------------------------------------
    # PASS 1: File Auditing & Graph Extraction
    # ---------------------------------------------------------
    for f in files:
        # 1. Isolate the Auditor (prevent crashes on weird files)
        try:
            report = audit_file(f)
        except Exception as e:
            print(f"  [ERROR] Auditor failed on {os.path.basename(f)}: {e}")
            report = {"findings": []}

        # 2. Extract AST data into the Knowledge Graph
        kg.analyze_file(f)
        
        # 3. Path Normalization for Vulnerabilities Dictionary
        # This guarantees the JSON keys match the UI node IDs exactly
        if report and report.get("findings"):
            abs_path = os.path.abspath(f)
            rel_path = os.path.relpath(abs_path, target_root)
            normalized_node_id = rel_path.replace(os.sep, '/')
            
            all_findings[normalized_node_id] = report["findings"]
            print(f"  [!] {os.path.basename(f)} -> {len(report['findings'])} ISSUES")
        else:
            print(f"  [✓] {os.path.basename(f)} -> CLEAN")

    # ---------------------------------------------------------
    # PASS 2: Connect the Edges
    # ---------------------------------------------------------
    print("\n[+] Resolving Cross-Language Dependencies & Edges...")
    kg.build_relationships()

    # ---------------------------------------------------------
    # State Persistence
    # ---------------------------------------------------------
    report_payload = {
        "nodes": kg.nodes,
        "edges": kg.edges,
        "vulnerabilities": all_findings
    }
    
    graph_tsx = sum(1 for metadata in kg.nodes.values() if metadata.get("lang", "") == 'tsx')
    print(f"[DEBUG] Knowledge Graph mapped {len(kg.nodes)} total nodes ({graph_tsx} are .tsx nodes)")
    print(f"[DEBUG] Knowledge Graph mapped {sum(len(v) for v in kg.edges.values())} total edges")

    with open('graph_report.json', 'w') as f_out:
        json.dump(report_payload, f_out, indent=4)

    print("\n" + "="*50)
    print("✅ ANALYSIS COMPLETE: Knowledge Graph Generated")
    print("="*50)

    # ---------------------------------------------------------
    # Trigger the Handshake (Start Server)
    # ---------------------------------------------------------
    port = get_free_port()
    server_thread = threading.Thread(
        target=start_titan_server, 
        args=(port,), 
        daemon=True
    )
    server_thread.start()

    try:
        print(f"\n[INFO] War Room live on port {port}. Press Ctrl+C to exit.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down Neuro-SP. War Room closed.")

if __name__ == "__main__":
    main()