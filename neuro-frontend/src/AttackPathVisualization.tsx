import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { 
    FileCode, 
    Activity, ZoomIn, ZoomOut,
    AlertTriangle, ShieldAlert, Crosshair
} from 'lucide-react';

/* ── Enterprise Type Definitions ────────────────────────────────── */
interface Vulnerability {
    type: string;
    line_number: number;
    entropy_score: number;
    snippet: string;
}

interface ScanNode {
    path: string;
    label?: string; 
    type: string; 
    is_entry?: boolean;
    in_degree?: number;
}

interface ScanData {
    nodes: Record<string, ScanNode>;
    edges: Record<string, string[]>;
    vulnerabilities: Record<string, Vulnerability[]>;
}

interface GraphNode extends ScanNode {
    id: string;
    x: number;
    y: number;
    iconComponent: React.ReactNode;
    color: string;
    vulnerabilities: Vulnerability[];
    isVulnerable: boolean;
    isUpstreamNode: boolean;
    isDownstreamNode: boolean;
}

// Graph Functional Colors - Left untouched per instructions
const COLORS = {
    SECURE: "#00D084",      
    CRITICAL: "#FF2B5E",    
    COMPROMISED: "#FF9A1F", 
    UPSTREAM: "#A855F7",    
    ACTIVE: "#0047FF",      
    LINE_DEFAULT: "#CBD5E1"
};

const FALLBACK_DATA: ScanData = {
    "nodes": {
        "/workspaces/Neuro-SP/neuro-frontend/src/AttackPathVisualization.tsx": {
            "path": "/workspaces/Neuro-SP/neuro-frontend/src/AttackPathVisualization.tsx",
            "label": "AttackPathVisualization.tsx",
            "type": "TSX_FILE",
            "is_entry": false,
            "in_degree": 0
        },
        "/workspaces/Neuro-SP/setup.py": {
            "path": "/workspaces/Neuro-SP/setup.py",
            "label": "setup.py",
            "type": "PY_FILE",
            "is_entry": false,
            "in_degree": 0
        },
        "/workspaces/Neuro-SP/neuroscan/crawler.py": {
            "path": "/workspaces/Neuro-SP/neuroscan/crawler.py",
            "label": "crawler.py",
            "type": "PY_FILE",
            "is_entry": false,
            "in_degree": 1
        },
        "/workspaces/Neuro-SP/neuroscan/auditor.py": {
            "path": "/workspaces/Neuro-SP/neuroscan/auditor.py",
            "label": "auditor.py",
            "type": "PY_FILE",
            "is_entry": false,
            "in_degree": 2
        },
        "/workspaces/Neuro-SP/neuroscan/vulnerable.test.py": {
            "path": "/workspaces/Neuro-SP/neuroscan/vulnerable.test.py",
            "label": "vulnerable.test.py",
            "type": "PY_FILE",
            "is_entry": false,
            "in_degree": 0
        },
        "/workspaces/Neuro-SP/neuroscan/graph.py": {
            "path": "/workspaces/Neuro-SP/neuroscan/graph.py",
            "label": "graph.py",
            "type": "PY_FILE",
            "is_entry": false,
            "in_degree": 1
        },
        "/workspaces/Neuro-SP/neuroscan/cli.py": {
            "path": "/workspaces/Neuro-SP/neuroscan/cli.py",
            "label": "cli.py",
            "type": "PY_FILE",
            "is_entry": false,
            "in_degree": 0
        }
    },
    "edges": {
        "/workspaces/Neuro-SP/neuroscan/vulnerable.test.py": [
            "/workspaces/Neuro-SP/neuroscan/auditor.py"
        ],
        "/workspaces/Neuro-SP/neuroscan/cli.py": [
            "/workspaces/Neuro-SP/neuroscan/crawler.py",
            "/workspaces/Neuro-SP/neuroscan/auditor.py",
            "/workspaces/Neuro-SP/neuroscan/graph.py"
        ]
    },
    "vulnerabilities": {
        "/workspaces/Neuro-SP/neuro-frontend/src/AttackPathVisualization.tsx": [
            { "type": "Insecure Eval", "line_number": 79, "entropy_score": 0, "snippet": "{ \"type\": \"Insecure Eval\", \"line_number\": 12, \"ent..." },
            { "type": "Command Injection Risk", "line_number": 80, "entropy_score": 0, "snippet": "{ \"type\": \"Command Injection Risk\", \"line_number\":..." },
            { "type": "Command Injection Risk", "line_number": 81, "entropy_score": 0, "snippet": "{ \"type\": \"Command Injection Risk\", \"line_number\":..." },
            { "type": "Insecure Deserialization", "line_number": 82, "entropy_score": 0, "snippet": "{ \"type\": \"Insecure Deserialization\", \"line_number..." }
        ],
        "/workspaces/Neuro-SP/neuroscan/crawler.py": [
            { "type": "Insecure Deserialization", "line_number": 22, "entropy_score": 0, "snippet": "pickle.loads(data)" }
        ],
        "/workspaces/Neuro-SP/neuroscan/vulnerable.test.py": [
            { "type": "Insecure Eval", "line_number": 14, "entropy_score": 0, "snippet": "eval(user_input)" },
            { "type": "Command Injection Risk", "line_number": 18, "entropy_score": 0, "snippet": "os.system(\"ls -la\")" },
            { "type": "Command Injection Risk", "line_number": 19, "entropy_score": 0, "snippet": "subprocess.run([\"echo\", \"Danger!\"])" },
            { "type": "Insecure Deserialization", "line_number": 24, "entropy_score": 0, "snippet": "pickle.loads(data)" }
        ]
    }
};

/* ── Tech Icon Mapper ── */
const TechIcon = ({ id, className }: { id: string; className?: string }) => {
    const ext = id.split('.').pop()?.toLowerCase();
    
    if (ext === 'py') return (
        <svg viewBox="0 0 24 24" className={className} fill="currentColor">
            <path d="M11.9 2C6.5 2 7 4.3 7 4.3l.1 1.7h4.9v.7H5.1S2 6.3 2 11.7c0 5.4 2.7 5.2 2.7 5.2l1.6-.1v-2.3s-.1-2.7 2.7-2.7h4.8s2.7.1 2.7-2.6V6.1S16.8 2 11.9 2zm-3.2 1.4c.5 0 .8.3.8.8s-.3.8-.8.8-.8-.3-.8-.8.3-.8.8-.8zM12.1 22c5.4 0 4.9-2.3 4.9-2.3l-.1-1.7H12v-.7h6.9s3.1.4 3.1-5c0-5.4-2.7-5.2-2.7-5.2l-1.6.1v2.3s.1 2.7-2.7 2.7H10.2s-2.7-.1-2.7 2.6v3.2S7.2 22 12.1 22zm3.2-1.4c-.5 0-.8-.3-.8-.8s.3-.8.8-.8.8.3.8.8-.3.8-.8.8z"/>
        </svg>
    );
    if (ext === 'java') return (
        <svg viewBox="0 0 24 24" className={className} fill="currentColor">
            <path d="M6 18.577s-2.071-.466-2.071-1.492c0-.853 1.398-1.399 1.398-1.399s-.144-.829.133-.92c.277-.09 1.127.351 1.127.351s.296-.549.774-.633c.478-.083 1.458.261 1.458.261s.334-.52.793-.52c.459 0 .878.143.878.143l.065.11s-.11.453-.11.751c0 .298.056.883.056.883s.772.368.772.934c0 .565-.67 1.054-.67 1.054s1.77 1.119.537 2.06c-1.232.94-5.143-.393-5.143-.393zm10.743-9.522s.672-.89 1.41-1.27c.738-.381 2.502-.857 2.502-.857s-1.83 0-2.827.81c-.997.808-1.54 2.21-1.54 2.21l.455-.893z"/>
        </svg>
    );
    if (['tsx', 'jsx', 'js'].includes(ext || '')) return (
        <svg viewBox="-11.5 -10.232 23 20.463" className={className} fill="none" stroke="currentColor" strokeWidth="1.2">
            <circle cx="0" cy="0" r="2.05" fill="currentColor" stroke="none"/>
            <g stroke="currentColor">
                <ellipse rx="11" ry="4.2"/><ellipse rx="11" ry="4.2" transform="rotate(60)"/><ellipse rx="11" ry="4.2" transform="rotate(120)"/>
            </g>
        </svg>
    );
    return <FileCode className={className} />;
};

export default function AttackPathVisualization() {
    const [scanData, setScanData] = useState<ScanData | null>(null);
    const [loading, setLoading] = useState(true);
    const [simState, setSimState] = useState<'idle' | 'running' | 'complete'>('idle');
    const [hasRunInitial, setHasRunInitial] = useState(false);
    
    const [scannedNodes, setScannedNodes] = useState<string[]>([]);
    const [currentTarget, setCurrentTarget] = useState<string | null>(null);

    /* ── Hardware-Accelerated Pan & Zoom Refs (Bypasses React Render Loop) ── */
    const transformRef = useRef({ x: 0, y: 0, scale: 0.9 });
    const isDraggingRef = useRef(false);
    const dragStartRef = useRef({ x: 0, y: 0 });
    
    const canvasContainerRef = useRef<HTMLDivElement>(null);
    const gridBgRef = useRef<HTMLDivElement>(null);

    // Apply the GPU-accelerated transform directly to the DOM
    const updateTransformDOM = useCallback(() => {
        if (canvasContainerRef.current) {
            canvasContainerRef.current.style.transform = `translate(${transformRef.current.x}px, ${transformRef.current.y}px) scale(${transformRef.current.scale})`;
        }
        if (gridBgRef.current) {
            gridBgRef.current.style.backgroundPosition = `${transformRef.current.x}px ${transformRef.current.y}px`;
            gridBgRef.current.style.backgroundSize = `${30 * transformRef.current.scale}px ${30 * transformRef.current.scale}px`;
        }
    }, []);

    // Ensure initial transform is applied on mount
    useEffect(() => {
        updateTransformDOM();
    }, [updateTransformDOM]);

    /* ── 1. Fetch Data ── */
    useEffect(() => {
        const loadData = async () => {
            try {
                const response = await fetch('/graph_report.json');
                if (!response.ok) throw new Error("Fetch failed");
                const data: ScanData = await response.json();
                setScanData(data);
            } catch (err) {
                console.warn("Using fallback data. Dynamic fetch failed:", err);
                setScanData(FALLBACK_DATA);
            } finally {
                setLoading(false);
            }
        };
        loadData();
    }, []);

    /* ── 2. Absolute Pixel Layout Engine (Prevents Intersections) ── */
    const graphData = useMemo(() => {
        if (!scanData) return { nodes: [] as GraphNode[] };

        const nodeKeys = Object.keys(scanData.nodes);
        
        // 1. Identify Vulnerable Nodes
        const vulnerableNodes = new Set<string>();
        nodeKeys.forEach(key => {
            const path = scanData.nodes[key].path || key;
            const vulns = scanData.vulnerabilities[path] || scanData.vulnerabilities[key] || [];
            if (vulns.length > 0) vulnerableNodes.add(key);
        });

        // 2. Compute Dynamic Upstream (Path TO vulnerability) and Downstream (Path FROM vulnerability)
        const upstreamNodes = new Set<string>();
        const downstreamNodes = new Set<string>();
        
        const reverseEdges: Record<string, string[]> = {};
        nodeKeys.forEach(k => reverseEdges[k] = []);
        Object.entries(scanData.edges).forEach(([source, targets]) => {
            targets.forEach(t => {
                if (!reverseEdges[t]) reverseEdges[t] = [];
                reverseEdges[t].push(source);
            });
        });

        // Traverse backwards from vulnerabilities to find Upstream nodes
        let queue = Array.from(vulnerableNodes);
        while(queue.length > 0) {
            const curr = queue.shift()!;
            (reverseEdges[curr] || []).forEach(parent => {
                if (!upstreamNodes.has(parent) && !vulnerableNodes.has(parent)) {
                    upstreamNodes.add(parent);
                    queue.push(parent);
                }
            });
        }

        // Traverse forwards from vulnerabilities to find Downstream nodes
        queue = Array.from(vulnerableNodes);
        while(queue.length > 0) {
            const curr = queue.shift()!;
            (scanData.edges[curr] || []).forEach(child => {
                if (!downstreamNodes.has(child) && !vulnerableNodes.has(child)) {
                    downstreamNodes.add(child);
                    queue.push(child);
                }
            });
        }

        const levels: Record<string, number> = {};
        nodeKeys.forEach(n => levels[n] = 0);
        let changed = true;
        while (changed) {
            changed = false;
            Object.entries(scanData.edges).forEach(([source, targets]) => {
                targets.forEach(target => {
                    if (levels[source] >= levels[target]) {
                        levels[target] = levels[source] + 1;
                        changed = true;
                    }
                });
            });
        }

        const levelGroups: Record<number, string[]> = {};
        nodeKeys.forEach(n => {
            const lvl = levels[n];
            if (!levelGroups[lvl]) levelGroups[lvl] = [];
            levelGroups[lvl].push(n);
        });

        const maxLevel = Math.max(0, ...Object.values(levels));

        // Layout Constants
        const HORIZONTAL_SPACING = 280; // Distance between columns
        const VERTICAL_SPACING = 120;   // Distance between rows

        const nodes = nodeKeys.map(key => {
            const data = scanData.nodes[key];
            const lvl = levels[key];
            const group = levelGroups[lvl];
            const idx = group.indexOf(key);
            
            // Center the entire graph around (0,0)
            const xOffset = (maxLevel * HORIZONTAL_SPACING) / 2;
            const x = (lvl * HORIZONTAL_SPACING) - xOffset;
            
            const yOffset = (group.length - 1) * VERTICAL_SPACING / 2;
            const y = (idx * VERTICAL_SPACING) - yOffset;

            const name = data.label || key.split('/').pop() || key;
            const ext = name.split('.').pop()?.toLowerCase();

            let color = "text-gray-400";
            if (ext === 'py') color = "text-[#0047FF]";
            else if (ext === 'java') color = "text-[#E11D48]";
            else if (['tsx', 'ts'].includes(ext || '')) color = "text-[#00D084]";

            const vulns = scanData.vulnerabilities[data.path] || scanData.vulnerabilities[key] || [];

            return {
                id: key,
                ...data,
                label: name,
                x, y,
                iconComponent: <TechIcon id={name} className="w-6 h-6" />,
                color,
                vulnerabilities: vulns,
                isVulnerable: vulnerableNodes.has(key),
                isUpstreamNode: upstreamNodes.has(key),
                isDownstreamNode: downstreamNodes.has(key)
            };
        });

        nodes.sort((a, b) => a.x - b.x);
        return { nodes };
    }, [scanData]);

    /* ── 3. Instant Load & Animated Replay Logic ── */
    useEffect(() => {
        if (scanData && graphData.nodes.length > 0 && !hasRunInitial) {
            const allScanned: string[] = [];

            graphData.nodes.forEach(node => {
                allScanned.push(node.id);
            });

            setScannedNodes(allScanned);
            setSimState('complete');
            setHasRunInitial(true);
        }
    }, [scanData, graphData, hasRunInitial]);

    useEffect(() => {
        if (simState !== 'running' || !scanData) return;

        const currentIndex = scannedNodes.length;
        
        if (currentIndex >= graphData.nodes.length) {
            setSimState('complete');
            setCurrentTarget(null);
            return;
        }

        const targetNode = graphData.nodes[currentIndex];
        setCurrentTarget(targetNode.id);

        const timer = setTimeout(() => {
            setScannedNodes(prev => [...prev, targetNode.id]);
        }, 150); 

        return () => clearTimeout(timer);
    }, [simState, scannedNodes, graphData.nodes, scanData]);

    /* ── DOM Hardware Acceleration Event Listeners ── */
    const handleWheel = useCallback((e: React.WheelEvent) => {
        const scaleChange = e.deltaY * -0.001;
        transformRef.current.scale = Math.min(Math.max(0.1, transformRef.current.scale + scaleChange), 4);
        requestAnimationFrame(updateTransformDOM);
    }, [updateTransformDOM]);

    const handleMouseDown = useCallback((e: React.MouseEvent) => {
        if (e.button !== 0) return; 
        isDraggingRef.current = true;
        dragStartRef.current = { 
            x: e.clientX - transformRef.current.x, 
            y: e.clientY - transformRef.current.y 
        };
    }, []);

    const handleMouseMove = useCallback((e: React.MouseEvent) => {
        if (!isDraggingRef.current) return;
        transformRef.current.x = e.clientX - dragStartRef.current.x;
        transformRef.current.y = e.clientY - dragStartRef.current.y;
        requestAnimationFrame(updateTransformDOM);
    }, [updateTransformDOM]);

    const handleMouseUp = useCallback(() => {
        isDraggingRef.current = false;
    }, []);

    const zoomIn = () => { transformRef.current.scale = Math.min(transformRef.current.scale + 0.2, 4); updateTransformDOM(); };
    const zoomOut = () => { transformRef.current.scale = Math.max(transformRef.current.scale - 0.2, 0.1); updateTransformDOM(); };
    const zoomReset = () => { transformRef.current.scale = 0.9; transformRef.current.x = 0; transformRef.current.y = 0; updateTransformDOM(); };

    if (loading) return (
        <div className="flex items-center justify-center min-h-screen bg-[#fbf9f8]">
            <Activity className="w-8 h-8 text-[#003fb7] animate-spin" />
        </div>
    );

    return (
        <div className="flex items-center justify-center min-h-screen bg-[#fbf9f8] p-4 lg:p-8 text-[#1b1c1c] font-sans"
             style={{fontFamily: "'Inter', system-ui, sans-serif"}}>
            
            {/* The Digital Curator Style: Inject Google Fonts for Inter & Plus Jakarta Sans */}
            <style dangerouslySetInnerHTML={{__html: `
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Plus+Jakarta+Sans:wght@500;600;700&display=swap');
                @keyframes fade-in-up { 0% { opacity: 0; transform: translateY(8px); } 100% { opacity: 1; transform: translateY(0); } }
                .animate-fade-in-up { animation: fade-in-up 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
                .custom-scrollbar::-webkit-scrollbar { width: 4px; }
                .custom-scrollbar::-webkit-scrollbar-thumb { background: #CBD5E1; border-radius: 4px; }
            `}} />

            {/* Ambient Shadow & No Borders structural styling */}
            <div className="w-full max-w-[1500px] h-[85vh] bg-[#ffffff] rounded-[1rem] shadow-[0_20px_40px_rgba(0,22,78,0.06)] flex flex-col overflow-hidden">
                {/* Glossy Gradient Header */}
                <div className="h-3 w-full bg-gradient-to-r from-[#003fb7] to-[#0254ec]"></div>
                
                <div className="flex flex-1 overflow-hidden">
                    {/* MAIN VISUALIZATION STAGE (Infinite Canvas) 
                        Takes full width since left panel is removed */}
                    <div className="flex-1 relative bg-[#fbf9f8] overflow-hidden flex flex-col w-full">
                        
                        {/* Header Overlay (Glassmorphism & Ghost Borders) */}
                        <div className="absolute top-0 w-full px-6 py-6 flex justify-between items-center z-20 pointer-events-none">
                            <h2 className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.1em] bg-[#ffffff]/70 backdrop-blur-xl px-4 py-2 rounded-lg border border-black/[0.05] shadow-[0_20px_40px_rgba(0,22,78,0.04)] font-['Plus_Jakarta_Sans']">
                                Attack Path Visualization
                            </h2>
                            <div className="flex gap-5 bg-[#ffffff]/70 backdrop-blur-xl px-5 py-2.5 rounded-lg border border-black/[0.05] shadow-[0_20px_40px_rgba(0,22,78,0.04)]">
                                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-[#A855F7]"></div><span className="text-[11px] font-semibold text-gray-600">Entry Point</span></div>
                                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-[#FF2B5E]"></div><span className="text-[11px] font-semibold text-gray-600">Origin of Risk</span></div>
                                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-[#FF9A1F]"></div><span className="text-[11px] font-semibold text-gray-600">Infected</span></div>
                            </div>
                        </div>

                        {/* Zoom Controls Overlay (Glassmorphism, No Dividers) */}
                        <div className="absolute bottom-8 right-8 z-20 flex gap-1 bg-[#ffffff]/70 backdrop-blur-xl border border-black/[0.05] p-1.5 rounded-xl shadow-[0_20px_40px_rgba(0,22,78,0.06)]">
                            <button onClick={zoomIn} className="p-2.5 text-gray-500 hover:bg-[#f5f3f3] hover:text-[#1b1c1c] rounded-lg transition-colors" title="Zoom In"><ZoomIn className="w-4 h-4"/></button>
                            <button onClick={zoomReset} className="p-2.5 text-gray-500 hover:bg-[#f5f3f3] hover:text-[#1b1c1c] rounded-lg transition-colors" title="Reset View"><Crosshair className="w-4 h-4"/></button>
                            <button onClick={zoomOut} className="p-2.5 text-gray-500 hover:bg-[#f5f3f3] hover:text-[#1b1c1c] rounded-lg transition-colors" title="Zoom Out"><ZoomOut className="w-4 h-4"/></button>
                        </div>

                        {/* Draggable & Zoomable Area (Uses requestAnimationFrame for 60fps) */}
                        <div 
                            className={`flex-1 relative cursor-grab active:cursor-grabbing overflow-hidden w-full`}
                            onWheel={handleWheel}
                            onMouseDown={handleMouseDown}
                            onMouseMove={handleMouseMove}
                            onMouseUp={handleMouseUp}
                            onMouseLeave={handleMouseUp}
                        >
                            {/* Dotted Grid Background - Managed by DOM Refs */}
                            <div ref={gridBgRef} className="absolute inset-0 pointer-events-none opacity-20"
                                style={{ backgroundImage: 'radial-gradient(#94a3b8 1.5px, transparent 0)' }}
                            />

                            {/* The Transform Container - Managed strictly by DOM Refs to prevent render lag */}
                            <div ref={canvasContainerRef} className="absolute top-1/2 left-1/2 w-0 h-0">
                                
                                {/* 1. SVGs Layer (Lines) */}
                                <svg className="absolute overflow-visible pointer-events-none z-0" style={{ top: 0, left: 0 }}>
                                    {graphData.nodes.map(source => {
                                        const edges = scanData?.edges[source.id] || [];
                                        const isSourceScanned = scannedNodes.includes(source.id);

                                        return edges.map(targetId => {
                                            const target = graphData.nodes.find(n => n.id === targetId);
                                            if (!target) return null;
                                            
                                            let edgeColor = COLORS.LINE_DEFAULT;
                                            let isActive = false;
                                            
                                            if (isSourceScanned) {
                                                if (source.isUpstreamNode && (target.isVulnerable || target.isUpstreamNode)) {
                                                    edgeColor = COLORS.UPSTREAM;
                                                    isActive = true;
                                                } 
                                                else if (source.isVulnerable || source.isDownstreamNode) {
                                                    edgeColor = COLORS.COMPROMISED;
                                                    isActive = true;
                                                }
                                            }
                                            
                                            const dist = Math.abs(target.x - source.x);
                                            const cp1x = source.x + (dist * 0.5);
                                            const cp2x = source.x + (dist * 0.5);
                                            
                                            const pathD = `M ${source.x} ${source.y} C ${cp1x} ${source.y}, ${cp2x} ${target.y}, ${target.x} ${target.y}`;
                                            return (
                                                <g key={`${source.id}-${targetId}`}>
                                                    <path 
                                                        d={pathD}
                                                        fill="none" 
                                                        stroke={edgeColor}
                                                        strokeWidth={isActive ? 3 : 1.5} 
                                                        className="transition-all duration-700" 
                                                    />
                                                    {!isActive && <circle cx={target.x} cy={target.y} r="3" fill={COLORS.LINE_DEFAULT} />}
                                                    
                                                    {isActive && simState === 'running' && (
                                                        <circle r="4" fill={edgeColor} className="drop-shadow-md">
                                                            <animateMotion dur="1s" repeatCount="indefinite" path={pathD} />
                                                        </circle>
                                                    )}
                                                </g>
                                            );
                                        });
                                    })}
                                </svg>

                                {/* 2. HTML Nodes Layer */}
                                {graphData.nodes.map(node => {
                                    const scanned = scannedNodes.includes(node.id);
                                    const current = currentTarget === node.id;
                                    
                                    return (
                                        <div key={node.id} 
                                             className="absolute -translate-x-1/2 -translate-y-1/2 transition-all duration-500 z-10 hover:z-50 flex flex-col items-center group pointer-events-auto"
                                             style={{ left: `${node.x}px`, top: `${node.y}px` }}>
                                            
                                            {/* Node Circle - Tonal layer with ambient shadow */}
                                            <div className={`relative w-14 h-14 rounded-full border-2 bg-[#ffffff] flex items-center justify-center ring-[6px] transition-all duration-300 shadow-[0_10px_30px_rgba(0,22,78,0.08)] group-hover:shadow-[0_20px_40px_rgba(0,22,78,0.12)]
                                                ${current ? 'border-[#003fb7] ring-blue-50/50 scale-110' : 
                                                  scanned && node.isVulnerable ? 'border-[#FF2B5E] ring-red-50/50' : 
                                                  scanned && node.isUpstreamNode ? 'border-[#A855F7] ring-purple-50/50' :
                                                  scanned && node.isDownstreamNode ? 'border-[#FF9A1F] ring-orange-50/50' : 'border-black/[0.05] ring-transparent group-hover:border-black/[0.1] text-gray-500'}`}>
                                                
                                                {current && <div className="absolute inset-0 rounded-full bg-[#003fb7]/10 animate-ping" />}
                                                <div className={`${current ? 'text-[#003fb7]' : scanned && node.isVulnerable ? 'text-[#FF2B5E]' : scanned && node.isUpstreamNode ? 'text-[#A855F7]' : scanned && node.isDownstreamNode ? 'text-[#FF9A1F]' : node.color}`}>
                                                    {node.iconComponent}
                                                </div>

                                                {scanned && node.isUpstreamNode && !node.isVulnerable && (
                                                    <div className="absolute -top-1.5 -right-1.5 w-5 h-5 bg-[#A855F7] rounded-full flex items-center justify-center shadow-sm border-2 border-white">
                                                        <Crosshair className="w-3 h-3 text-white" strokeWidth={3} />
                                                    </div>
                                                )}

                                                {scanned && node.isVulnerable && (
                                                    <div className="absolute -top-1.5 -right-1.5 w-5 h-5 bg-[#FF2B5E] rounded-full flex items-center justify-center shadow-sm border-2 border-white">
                                                        <AlertTriangle className="w-3 h-3 text-white" strokeWidth={3} />
                                                    </div>
                                                )}

                                                {scanned && node.isDownstreamNode && !node.isVulnerable && (
                                                    <div className="absolute -top-1.5 -right-1.5 w-5 h-5 bg-[#FF9A1F] rounded-full flex items-center justify-center shadow-sm border-2 border-white">
                                                        <ShieldAlert className="w-3 h-3 text-white" strokeWidth={3} />
                                                    </div>
                                                )}
                                            </div>
                                            
                                            {/* Node Label Container */}
                                            <div className="absolute top-full mt-4 flex flex-col items-center w-max pointer-events-none">
                                                <div className="text-[12px] font-medium px-3 py-1.5 bg-[#ffffff] border border-black/[0.05] rounded-md shadow-[0_8px_20px_rgba(0,22,78,0.06)] text-[#1b1c1c] tracking-tight whitespace-nowrap">
                                                    {node.label}
                                                </div>
                                            </div>

                                            {/* Tooltip on Hover (Refined to match Tonal Layering and Error Container logic) */}
                                            {node.vulnerabilities && node.vulnerabilities.length > 0 && scanned && (
                                                <div 
                                                    className="absolute left-full top-0 pl-6 w-[22rem] opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-300 z-50"
                                                    onWheel={(e) => e.stopPropagation()}
                                                >
                                                    <div className="bg-[#ffffff] border border-black/[0.05] shadow-[0_20px_40px_rgba(0,22,78,0.1)] rounded-xl p-4 relative before:content-[''] before:absolute before:top-5 before:-left-2 before:w-4 before:h-4 before:bg-white before:border-l before:border-b before:border-black/[0.05] before:rotate-45">
                                                        <h4 className="text-xs font-bold text-[#1b1c1c] mb-3 flex items-center gap-2 relative z-10 font-['Plus_Jakarta_Sans']">
                                                            <AlertTriangle className="w-4 h-4 text-[#ba1a1a]" />
                                                            Vulnerabilities ({node.vulnerabilities.length})
                                                        </h4>
                                                        
                                                        {/* Zero-Divider Policy applied here: Using space-y-3 instead of borders */}
                                                        <div className="space-y-3 max-h-64 overflow-y-auto relative z-10 pr-2 custom-scrollbar">
                                                            {node.vulnerabilities.map((v, i) => (
                                                                // Using error container for soft background fill
                                                                <div key={i} className="text-[11px] leading-tight bg-[#ba1a1a]/5 p-3 rounded-lg border border-transparent">
                                                                    <div className="font-bold text-[#ba1a1a] flex justify-between items-center mb-2">
                                                                        <span className="truncate pr-3">{v.type}</span>
                                                                        <span className="bg-[#ffffff] px-2 py-1 rounded shadow-sm text-gray-700 whitespace-nowrap font-medium text-[10px]">Line {v.line_number}</span>
                                                                    </div>
                                                                    <div className="font-mono text-[10px] text-gray-700 truncate bg-[#ffffff] px-2.5 py-2 rounded shadow-sm">
                                                                        {v.snippet}
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}