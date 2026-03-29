import React, { useState, useEffect, useMemo } from 'react';
import { 
    Shield, Play, RotateCcw, FileCode, 
    Activity, Sparkles,
    AlertTriangle, ShieldAlert, ChevronRight
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
    type: string; 
    is_entry: boolean;
    in_degree: number;
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
}

interface LogEntry {
    type: 'info' | 'alert' | 'warning' | 'success';
    title: string;
    message: string;
    action?: string;
}

const COLORS = {
    SECURE: "#00D084",      // Wiz Emerald
    CRITICAL: "#FF2B5E",    // Wiz Magenta
    COMPROMISED: "#FF9A1F", // Wiz Amber
    ACTIVE: "#0047FF",      // Wiz Electric Blue
};

/* ── Tech Icon Mapper (Wiz-Style) ── */
const TechIcon = ({ id, className }: { id: string; className?: string }) => {
    const ext = id.split('.').pop()?.toLowerCase();
    
    // Python Logo
    if (ext === 'py') return (
        <svg viewBox="0 0 24 24" className={className} fill="currentColor">
            <path d="M11.9 2C6.5 2 7 4.3 7 4.3l.1 1.7h4.9v.7H5.1S2 6.3 2 11.7c0 5.4 2.7 5.2 2.7 5.2l1.6-.1v-2.3s-.1-2.7 2.7-2.7h4.8s2.7.1 2.7-2.6V6.1S16.8 2 11.9 2zm-3.2 1.4c.5 0 .8.3.8.8s-.3.8-.8.8-.8-.3-.8-.8.3-.8.8-.8zM12.1 22c5.4 0 4.9-2.3 4.9-2.3l-.1-1.7H12v-.7h6.9s3.1.4 3.1-5c0-5.4-2.7-5.2-2.7-5.2l-1.6.1v2.3s.1 2.7-2.7 2.7H10.2s-2.7-.1-2.7 2.6v3.2S7.2 22 12.1 22zm3.2-1.4c-.5 0-.8-.3-.8-.8s.3-.8.8-.8.8.3.8.8-.3.8-.8.8z"/>
        </svg>
    );
    // Java Logo
    if (ext === 'java') return (
        <svg viewBox="0 0 24 24" className={className} fill="currentColor">
            <path d="M6 18.577s-2.071-.466-2.071-1.492c0-.853 1.398-1.399 1.398-1.399s-.144-.829.133-.92c.277-.09 1.127.351 1.127.351s.296-.549.774-.633c.478-.083 1.458.261 1.458.261s.334-.52.793-.52c.459 0 .878.143.878.143l.065.11s-.11.453-.11.751c0 .298.056.883.056.883s.772.368.772.934c0 .565-.67 1.054-.67 1.054s1.77 1.119.537 2.06c-1.232.94-5.143-.393-5.143-.393zm10.743-9.522s.672-.89 1.41-1.27c.738-.381 2.502-.857 2.502-.857s-1.83 0-2.827.81c-.997.808-1.54 2.21-1.54 2.21l.455-.893z"/>
        </svg>
    );
    // React/TSX Logo
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
    const [scannedNodes, setScannedNodes] = useState<string[]>([]);
    const [attackLogs, setAttackLogs] = useState<LogEntry[]>([]);
    const [currentTarget, setCurrentTarget] = useState<string | null>(null);
    const [affectedNodes, setAffectedNodes] = useState<Set<string>>(new Set());
    const [activeEdges, setActiveEdges] = useState<string[]>([]);

    /* ── 1. Fetch Real-Time Data ── */
    useEffect(() => {
        const loadData = async () => {
            try {
                const response = await fetch('/graph_report.json');
                const data: ScanData = await response.json();
                setScanData(data);
            } catch (err) {
                console.error("Titan Engine Connection Failed:", err);
            } finally {
                setLoading(false);
            }
        };
        loadData();
    }, []);

    /* ── 2. Fully Dynamic DAG Layout Engine ── */
    const graphData = useMemo(() => {
        if (!scanData) return { nodes: [] as GraphNode[] };
        const nodeKeys = Object.keys(scanData.nodes);

        return {
            nodes: nodeKeys.map((key, index) => {
                const data = scanData.nodes[key];
                const ext = key.split('.').pop()?.toLowerCase();
                
                // Identify all unique nodes from both the 'nodes' definition and 'vulnerabilities'
                const x = data.in_degree === 0 ? 15 : Math.min(45 + (data.in_degree * 12), 85);
                const y = 20 + ((index % 6) * 14);

                let color = "text-gray-400";
                if (ext === 'py') color = "text-[#0047FF]";
                else if (ext === 'java') color = "text-[#E11D48]";
                else if (['tsx', 'ts'].includes(ext || '')) color = "text-[#00D084]";

                const vulns = scanData.vulnerabilities[data.path] || [];

                return {
                    id: key,
                    ...data,
                    x, y,
                    iconComponent: <TechIcon id={key} className="w-6 h-6" />,
                    color,
                    vulnerabilities: vulns,
                    isVulnerable: vulns.length > 0
                };
            })
        };
    }, [scanData]);

    /* ── 3. Simulation Logic ── */
    useEffect(() => {
        if (simState !== 'running' || !scanData) return;
        const currentIndex = scannedNodes.length;

        if (currentIndex >= graphData.nodes.length) {
            setSimState('complete');
            setCurrentTarget(null);
            setAttackLogs(prev => [...prev, { 
                type: 'info', title: 'Scan Complete', message: 'No further active exploitation detected.' 
            }]);
            return;
        }

        const targetNode = graphData.nodes[currentIndex];
        setCurrentTarget(targetNode.id);

        const timer = setTimeout(() => {
            setScannedNodes(prev => [...prev, targetNode.id]);
            
            if (targetNode.isVulnerable) {
                setAttackLogs(prev => [...prev, { 
                    type: 'alert', title: `Critical Risk: ${targetNode.id}`,
                    message: `Found ${targetNode.vulnerabilities.length} severe vulnerabilities detected.`,
                    action: 'Fix assigned to @security-team'
                }]);

                const outboundEdges = scanData.edges[targetNode.id] || [];
                if (outboundEdges.length > 0) {
                    setTimeout(() => {
                        setActiveEdges(prev => [...prev, ...outboundEdges.map(id => `${targetNode.id}-${id}`)]);
                        setAffectedNodes(prev => {
                            const next = new Set(prev);
                            outboundEdges.forEach(id => next.add(id));
                            return next;
                        });
                    }, 500);
                }
            }
        }, 1000);

        return () => clearTimeout(timer);
    }, [simState, scannedNodes, graphData.nodes, scanData]);

    const handleStart = () => {
        setSimState('running');
        setScannedNodes([]);
        setAttackLogs([{ type: 'info', title: 'Initializing Scan', message: 'Starting AI-powered tracing across your environment...' }]);
        setAffectedNodes(new Set());
        setActiveEdges([]);
    };

    const handleReset = () => {
        setSimState('idle');
        setScannedNodes([]);
        setAttackLogs([]);
        setCurrentTarget(null);
        setAffectedNodes(new Set());
        setActiveEdges([]);
    };

    if (loading) return (
        <div className="flex items-center justify-center min-h-screen bg-[#f3f5f9]">
            <Activity className="w-8 h-8 text-[#0047FF] animate-spin" />
        </div>
    );

    return (
        <div className="flex items-center justify-center min-h-screen bg-[#f3f5f9] p-8 font-sans text-gray-800"
             style={{fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"}}>
            
            <div className="w-full max-w-[1400px] h-[800px] bg-white rounded-[1rem] shadow-[0_12px_40px_rgba(0,0,0,0.08)] border border-gray-200 flex flex-col overflow-hidden">
                <div className="h-3 w-full bg-[#0047FF]"></div>

                <div className="flex flex-1 overflow-hidden">
                    {/* LEFT PANEL: Ask AI / Telemetry */}
                    <div className="w-[380px] border-r border-gray-200 bg-white flex flex-col z-10">
                        <div className="p-5 border-b border-gray-100 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <Sparkles className="w-5 h-5 text-purple-500" />
                                <h2 className="text-lg font-bold">Ask AI</h2>
                            </div>
                            <div className="flex gap-2">
                                <button onClick={handleReset} className="p-1.5 text-gray-400 hover:bg-gray-100 rounded-md transition-colors">
                                    <RotateCcw className="w-4 h-4" />
                                </button>
                                <button onClick={handleStart} disabled={simState === 'running'}
                                        className="px-4 py-1.5 bg-[#0047FF] text-white text-sm font-bold rounded-lg flex items-center gap-2 disabled:opacity-50 hover:bg-blue-700 transition-all">
                                    {simState === 'running' ? <Activity className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                                    Run
                                </button>
                            </div>
                        </div>

                        <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-gray-50/30">
                            {attackLogs.map((log, idx) => (
                                <div key={idx} className="p-4 bg-white border border-gray-100 rounded-xl shadow-sm animate-fade-in-up">
                                    <div className="flex items-start gap-3">
                                        <div className={`mt-0.5 ${log.type === 'alert' ? 'text-red-500' : 'text-blue-500'}`}>
                                            {log.type === 'alert' ? <ShieldAlert className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
                                        </div>
                                        <div>
                                            <h4 className="text-sm font-bold">{log.title}</h4>
                                            <p className="text-xs text-gray-500 mt-1 leading-relaxed">{log.message}</p>
                                            {log.action && <p className="text-[10px] font-bold text-blue-600 mt-2 uppercase tracking-tighter">● {log.action}</p>}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>

                        <div className="p-4 border-t bg-white">
                            <div className="relative">
                                <input type="text" placeholder="Ask anything..." className="w-full pl-4 pr-10 py-3 bg-gray-50 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all" />
                                <ChevronRight className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                            </div>
                        </div>
                    </div>

                    {/* MAIN VISUALIZATION STAGE */}
                    <div className="flex-1 relative bg-white overflow-hidden">
                        <div className="px-8 py-5 border-b border-gray-100 flex justify-between items-center bg-white/80 backdrop-blur-md z-10 relative">
                            <h2 className="text-[11px] font-bold text-gray-400 uppercase tracking-[0.2em]">Attack Path Visualization</h2>
                            <div className="flex gap-4">
                                <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-[#FF2B5E]"></div><span className="text-[10px] font-bold text-gray-500">CRITICAL</span></div>
                                <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-[#FF9A1F]"></div><span className="text-[10px] font-bold text-gray-500">COMPROMISED</span></div>
                            </div>
                        </div>

                        <div className="absolute inset-0 top-16">
                            {/* Bezier Connections */}
                            <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 100 100" preserveAspectRatio="none">
                                {graphData.nodes.map(source => {
                                    const edges = scanData?.edges[source.id] || [];
                                    return edges.map(targetId => {
                                        const target = graphData.nodes.find(n => n.id === targetId);
                                        if (!target) return null;
                                        const active = activeEdges.includes(`${source.id}-${targetId}`);
                                        
                                        // Curve calculation
                                        const cp1x = source.x + (target.x - source.x) / 2;
                                        const cp2x = source.x + (target.x - source.x) / 2;

                                        return (
                                            <path key={`${source.id}-${targetId}`}
                                                  d={`M ${source.x} ${source.y} C ${cp1x} ${source.y}, ${cp2x} ${target.y}, ${target.x} ${target.y}`}
                                                  fill="none" stroke={active ? COLORS.COMPROMISED : "#E5E7EB"}
                                                  strokeWidth={active ? 0.6 : 0.2} vectorEffect="non-scaling-stroke"
                                                  className="transition-all duration-700" />
                                        );
                                    });
                                })}
                            </svg>

                            {/* Nodes */}
                            {graphData.nodes.map(node => {
                                const scanned = scannedNodes.includes(node.id);
                                const current = currentTarget === node.id;
                                const affected = affectedNodes.has(node.id);
                                
                                return (
                                    <div key={node.id} className="absolute -translate-x-1/2 -translate-y-1/2 transition-all duration-500 z-20"
                                         style={{ left: `${node.x}%`, top: `${node.y}%` }}>
                                        <div className={`relative w-12 h-12 rounded-full border-2 bg-white flex items-center justify-center shadow-sm ring-[6px] transition-all
                                            ${current ? 'border-[#0047FF] ring-blue-50 scale-110' : 
                                              scanned && node.isVulnerable ? 'border-[#FF2B5E] ring-red-50' : 
                                              affected ? 'border-[#FF9A1F] ring-orange-50' : 'border-gray-100 ring-transparent'}`}>
                                            
                                            <div className={`${current ? 'text-[#0047FF]' : scanned && node.isVulnerable ? 'text-[#FF2B5E]' : affected ? 'text-[#FF9A1F]' : node.color}`}>
                                                {node.iconComponent}
                                            </div>

                                            {scanned && node.isVulnerable && (
                                                <div className="absolute -top-1 -right-1 w-4 h-4 bg-[#FF2B5E] rounded-full flex items-center justify-center shadow-sm animate-bounce">
                                                    <AlertTriangle className="w-2.5 h-2.5 text-white" />
                                                </div>
                                            )}
                                        </div>
                                        <div className="mt-3 text-center whitespace-nowrap">
                                            <div className="text-[10px] font-bold px-2 py-0.5 bg-white border border-gray-100 rounded shadow-sm text-gray-600 tracking-tighter">
                                                {node.id}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                </div>
            </div>

            <style dangerouslySetInnerHTML={{__html: `
                @keyframes fade-in-up { 0% { opacity: 0; transform: translateY(8px); } 100% { opacity: 1; transform: translateY(0); } }
                .animate-fade-in-up { animation: fade-in-up 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
            `}} />
        </div>
    );
}