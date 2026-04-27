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

def get_blast_radius(full_nodes, full_edges, vulnerabilities, max_depth=2):
    """
    Filters 10M+ nodes down to the critical 'Blast Radius'.
    Traces both UPSTREAM (Who calls me?) and DOWNSTREAM (What do I call?).
    """
    if not vulnerabilities:
        return {"nodes": {}, "edges": {}, "vulnerabilities": {}}

    critical_files = list(vulnerabilities.keys())
    relevant_nodes = set(critical_files)
    
    # ── BFS Path Tracing ──
    for _ in range(max_depth):
        new_nodes = set()
        for node in list(relevant_nodes):
            # UPSTREAM: Who imports this node?
            parents = [k for k, v in full_edges.items() if node in v]
            new_nodes.update(parents)
            
            # DOWNSTREAM: What does this node import?
            children = full_edges.get(node, [])
            new_nodes.update(children)
        
        relevant_nodes.update(new_nodes)
        if not new_nodes:
            break # Optimization: Stop tracing if we hit dead ends

    # ── Global Anchors (The Safety Net) ──
    anchors = {"setup.py", "Dockerfile", "package.json", "requirements.txt", ".env"}
    # Use basename to match full paths (e.g., /workspace/setup.py -> setup.py)
    found_anchors = [f for f in full_nodes.keys() if os.path.basename(f) in anchors]
    relevant_nodes.update(found_anchors)

    # ── Final Slice (with Bulletproof Edge Check) ──
    filtered_nodes = {k: v for k, v in full_nodes.items() if k in relevant_nodes}
    filtered_edges = {k: [target for target in v if target in relevant_nodes] 
                      for k, v in full_edges.items() if k in relevant_nodes}
    
    return {
        "nodes": filtered_nodes, 
        "edges": filtered_edges, 
        "vulnerabilities": vulnerabilities,
        "anchors": [os.path.basename(a) for a in found_anchors] # Clean names for the UI
    }

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

    print("\n[+] Initializing Neuro-SP [TITAN MODE]...")
    kg = KnowledgeGraph(args.target)
    files = discover_files(args.target)
    
    all_findings = {}
    for f in files:
        report = audit_file(f)
        kg.analyze_file(f)
        if report.get("findings"):
            all_findings[f] = report["findings"]
            print(f"  [!] {f} -> {len(report['findings'])} ISSUES")
        else:
            print(f"  [✓] {f} -> CLEAN")

    # 3. State Persistence (PRD Section 3.A) - UPDATED FOR TITAN BLAST RADIUS
    print(f"\n[*] Extracting Blast Radius from {len(kg.nodes)} total nodes...")
    report_payload = get_blast_radius(kg.nodes, kg.edges, all_findings)
    print(f"[+] Payload optimized: {len(report_payload['nodes'])} critical nodes identified.")

    with open('graph_report.json', 'w') as f_out:
        json.dump(report_payload, f_out, indent=4)

    print("\n" + "="*50)
    print("✅ ANALYSIS COMPLETE: Knowledge Graph Generated")
    print("="*50)

    # 4. Trigger the Handshake (PRD Section 3.A)
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