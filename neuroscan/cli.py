import argparse
import json
import webbrowser
from neuroscan.crawler import discover_files
from neuroscan.auditor import audit_file
from neuroscan.graph import KnowledgeGraph

def main():
    parser = argparse.ArgumentParser(description="Neuro-SP Security Scanner")
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--target", type=str, default=".")
    args = parser.parse_args()

    if args.analyze:
        print("\n[+] Initializing Neuro-SP Engine...")
        kg = KnowledgeGraph(args.target)
        
        files = discover_files(args.target)
        print(f"[*] Scanning {len(files)} files for vulnerabilities...\n")
        
        all_findings = {}
        for f in files:
            report = audit_file(f)
            kg.analyze_file(f)
            
            if report.get("findings"):
                all_findings[f] = report["findings"]
                print(f"  [!] {f} -> {len(report['findings'])} ISSUES")
            else:
                print(f"  [✓] {f} -> CLEAN")

        # Export for Frontend
        report_payload = {
            "nodes": kg.nodes,
            "edges": kg.edges,
            "vulnerabilities": all_findings
        }
        
        with open('graph_report.json', 'w') as f:
            json.dump(report_payload, f, indent=4)

        print("\n" + "="*50)
        print("✅ ANALYSIS COMPLETE: Knowledge Graph Generated")
        print("="*50)
        
        url = "http://localhost:3000/war-room"
        print(f"\n[➔] View Interactive Heatmap: \033[4;34m{url}\033[0m")
        
        # Auto-launch browser
        webbrowser.open(url)

if __name__ == "__main__":
    main()