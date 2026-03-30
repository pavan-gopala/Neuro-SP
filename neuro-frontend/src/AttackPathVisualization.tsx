import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import type { ReactNode } from 'react';
import { 
    Shield, CheckCircle, Activity, ShieldAlert, X,  
} from 'lucide-react';
import Graph from 'graphology';
import Sigma from 'sigma';
import forceAtlas2 from 'graphology-layout-forceatlas2';

/* ── Types & Interfaces ───────────────────────────────────────── */

interface VulnerabilityData {
    type: string;
    line_number: number;
    snippet: string;
}

interface RawNode {
    path: string;
    type: string;
    lang: string;
    is_entry?: boolean;
    in_degree: number;
    out_degree: number;
}

interface RawData {
    nodes: Record<string, RawNode>;
    edges: Record<string, string[]>;
    vulnerabilities: Record<string, VulnerabilityData[]>;
}

interface GraphNode {
    id: string;
    label: string;
    fullPath: string;
    lang?: string;
    x: number;
    y: number;
    vx: number;
    vy: number;
    ax: number;
    isVulnerable: boolean;
}

interface GraphEdge {
    source: string;
    target: string;
}

interface GraphData {
    nodes: GraphNode[];
    edges: GraphEdge[];
    vulnerabilities: Record<string, VulnerabilityData[]>;
}

/* ── Constants & Theme (Digital Curator Design System) ────────── */

const COLORS = {
    PRIMARY: "#003fb7",
    PRIMARY_CONTAINER: "#0254ec",
    SECURE: "#008a58",
    CRITICAL: "#d91e4a",
    COMPROMISED: "#d97e1a",
    NEUTRAL: "#9ca3af",
    SURFACE: "#fbf9f8",
    SURFACE_LOW: "#f5f3f3",
    ON_SURFACE: "#1b1c1c",
    EDGE: "#d1d5db",
};

const SURFACE_BG = '#fbf9f8';

const processData = (rawData: RawData): GraphData => {
    const nodes: GraphNode[] = Object.entries(rawData.nodes).map(([id, node]) => ({
        id,
        label: id.split('/').pop() || id,
        fullPath: id,
        lang: node.lang || 'unknown',
        x: Math.random() * 800 + 100,
        y: Math.random() * 600 + 100,
        vx: (Math.random() - 0.5) * 2,
        vy: 0,
        ax: 0,
        isVulnerable: !!rawData.vulnerabilities[id],
    }));

    const edges: GraphEdge[] = [];
    Object.entries(rawData.edges).forEach(([source, targets]) => {
        targets.forEach(target => edges.push({ source, target }));
    });

    return { nodes, edges, vulnerabilities: rawData.vulnerabilities };
};

/* ── Sigma.js Graph Component ──────────────────────────────────── */

interface CanvasGraphProps {
    data: GraphData;
    scannedNodes: string[];
    affectedNodes: Set<string>;
    onNodeClick: (node: GraphNode) => void;
}

const CanvasGraph: React.FC<CanvasGraphProps> = ({ data, scannedNodes, affectedNodes, onNodeClick }) => {
    const containerRef = useRef<HTMLDivElement>(null);
    // Overlay canvas rendered above Sigma's WebGL canvas for custom hollow-ring + icon nodes
    const overlayRef   = useRef<HTMLCanvasElement>(null);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sigmaRef = useRef<any>(null);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const graphRef = useRef<any>(null);
    const onNodeClickRef = useRef(onNodeClick);

    // Mutable ref so the stable afterRender callback always sees fresh state
    const stateRef = useRef({ scannedNodes, affectedNodes, data });

    useEffect(() => { onNodeClickRef.current = onNodeClick; }, [onNodeClick]);

    // Sync state ref then ask Sigma to re-render (→ afterRender → drawOverlay)
    useEffect(() => {
        stateRef.current = { scannedNodes, affectedNodes, data };

        const graph = graphRef.current;
        const sigma = sigmaRef.current;
        if (!graph || !sigma) return;

        // Update edge colours in graphology so Sigma's edge renderer stays in sync
        data.edges.forEach(edge => {
            try {
                if (!graph.hasDirectedEdge(edge.source, edge.target)) return;
                const edgeKey = graph.directedEdge(edge.source, edge.target);
                if (edgeKey === undefined) return;
                const isActive = scannedNodes.includes(edge.source) && affectedNodes.has(edge.target);
                graph.setEdgeAttribute(edgeKey, 'color', isActive ? COLORS.COMPROMISED : COLORS.EDGE);
                graph.setEdgeAttribute(edgeKey, 'size',  isActive ? 2.5 : 1);
            } catch (_) {}
        });

        sigma.refresh();
    }, [scannedNodes, affectedNodes, data]);

    // ── Overlay draw (stable — reads only from stateRef) ──────────────────────
    const drawOverlay = useCallback(() => {
        const canvas = overlayRef.current;
        const sigma  = sigmaRef.current;
        const graph  = graphRef.current;
        if (!canvas || !sigma || !graph) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        const { scannedNodes, affectedNodes, data } = stateRef.current;

        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.save();

        graph.nodes().forEach((nodeId: string) => {
            const attrs = graph.getNodeAttributes(nodeId);
            // graphToViewport converts graph-space → CSS-pixel screen coords,
            // fully accounting for current camera pan and zoom
            const { x, y } = sigma.graphToViewport({ x: attrs.x, y: attrs.y });

            const nodeData = data.nodes.find((n: GraphNode) => n.id === nodeId);
            if (!nodeData) return;

            const isScanned    = scannedNodes.includes(nodeId);
            const isAffected   = affectedNodes.has(nodeId);
            const isVulnerable = nodeData.isVulnerable;

            let borderColor = COLORS.NEUTRAL;
            let borderWidth = 2;
            let radius = 11;

            if (isScanned) {
                borderColor = isVulnerable ? COLORS.CRITICAL : COLORS.SECURE;
                borderWidth = 2.5;
                radius = 13;
            } else if (isAffected) {
                borderColor = COLORS.COMPROMISED;
                borderWidth = 2.5;
                radius = 12;
            }

            // ── Hollow circle: fill with surface colour (clips edge lines that
            //    pass through), then stroke the coloured ring ─────────────────
            ctx.beginPath();
            ctx.arc(x, y, radius, 0, Math.PI * 2);
            ctx.fillStyle = SURFACE_BG;
            ctx.fill();
            ctx.lineWidth   = borderWidth;
            ctx.strokeStyle = borderColor;
            ctx.stroke();

            // ── ☠ attacker symbol inside vulnerable + scanned nodes ──────────
            if (isVulnerable && isScanned) {
                ctx.font         = `${Math.round(radius * 1.35)}px serif`;
                ctx.textAlign    = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle    = COLORS.CRITICAL;
                ctx.fillText('☠', x, y);
            }
        });

        ctx.restore();
    }, []);

    // ── One-time Sigma initialisation ──────────────────────────────────────────
    useEffect(() => {
        if (!containerRef.current) return;

        const graph = new Graph({ type: 'directed' });
        graphRef.current = graph;

        data.nodes.forEach(node => {
            graph.addNode(node.id, {
                x: Math.random() * 20 - 10,
                y: Math.random() * 20 - 10,
                // Keep size non-zero so Sigma's hit-test matches the visible ring
                size: 13,
                label: node.label,
                // Match background → Sigma's own dot is invisible; overlay draws the ring
                color: SURFACE_BG,
            });
        });

        data.edges.forEach(edge => {
            try {
                if (
                    graph.hasNode(edge.source) &&
                    graph.hasNode(edge.target) &&
                    !graph.hasDirectedEdge(edge.source, edge.target)
                ) {
                    graph.addDirectedEdge(edge.source, edge.target, {
                        color: COLORS.EDGE,
                        size: 1,
                    });
                }
            } catch (_) {}
        });

        // ── Run ForceAtlas2 fully synchronously — zero animation frames ───────
        // High scalingRatio = strong repulsion = nodes spread apart generously.
        const settings = {
            ...forceAtlas2.inferSettings(graph),
            gravity: 0.5,
            scalingRatio: 18,
            slowDown: 1,
            barnesHutOptimize: graph.order > 60,
        };
        forceAtlas2.assign(graph, { iterations: 600, settings });

        // ── Hard minimum-distance pass ────────────────────────────────────────
        // Guarantees no two nodes are closer than MIN_DIST graph-units,
        // regardless of how the FA2 force balance settled.
        const MIN_DIST = 4;
        const nodeIds  = graph.nodes();
        for (let pass = 0; pass < 40; pass++) {
            let anyMoved = false;
            for (let i = 0; i < nodeIds.length; i++) {
                for (let j = i + 1; j < nodeIds.length; j++) {
                    const a  = graph.getNodeAttributes(nodeIds[i]);
                    const b  = graph.getNodeAttributes(nodeIds[j]);
                    const dx = b.x - a.x;
                    const dy = b.y - a.y;
                    const d  = Math.sqrt(dx * dx + dy * dy) || 0.001;
                    if (d < MIN_DIST) {
                        const push = (MIN_DIST - d) / 2 + 0.01;
                        const ux   = (dx / d) * push;
                        const uy   = (dy / d) * push;
                        graph.setNodeAttribute(nodeIds[i], 'x', a.x - ux);
                        graph.setNodeAttribute(nodeIds[i], 'y', a.y - uy);
                        graph.setNodeAttribute(nodeIds[j], 'x', b.x + ux);
                        graph.setNodeAttribute(nodeIds[j], 'y', b.y + uy);
                        anyMoved = true;
                    }
                }
            }
            if (!anyMoved) break;
        }

        // ── Create Sigma instance ─────────────────────────────────────────────
        const sigma = new Sigma(graph, containerRef.current, {
            renderEdgeLabels: false,
            labelFont:        'Inter, sans-serif',
            labelSize:        11,
            labelWeight:      '500',
            labelColor:       { color: COLORS.ON_SURFACE },
            defaultEdgeColor: COLORS.EDGE,
            defaultNodeColor: SURFACE_BG,
            minCameraRatio:   0.3,
            maxCameraRatio:   3,
        });
        sigmaRef.current = sigma;

        sigma.on('clickNode', ({ node }: { node: string }) => {
            const nodeData = data.nodes.find(n => n.id === node);
            if (nodeData) onNodeClickRef.current(nodeData);
        });

        // Every time Sigma redraws, re-paint the overlay on top
        sigma.on('afterRender', drawOverlay);

        // ── Keep overlay canvas pixel-perfectly sized to its container ────────
        const syncOverlaySize = () => {
            const overlay   = overlayRef.current;
            const container = containerRef.current;
            if (!overlay || !container) return;
            overlay.width        = container.clientWidth;
            overlay.height       = container.clientHeight;
            overlay.style.width  = container.clientWidth  + 'px';
            overlay.style.height = container.clientHeight + 'px';
        };

        syncOverlaySize();
        sigma.refresh(); // first paint — layout is already final

        const ro = new ResizeObserver(() => { syncOverlaySize(); sigma.refresh(); });
        ro.observe(containerRef.current);

        return () => {
            ro.disconnect();
            sigma.kill();
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [data, drawOverlay]);

    return (
        <div ref={containerRef} style={{ position: 'absolute', inset: 0 }}>
            {/* Overlay sits above Sigma's canvas; pointer-events:none lets all
                mouse/touch events fall through to Sigma for pan, zoom & click */}
            <canvas
                ref={overlayRef}
                style={{
                    position: 'absolute',
                    inset: 0,
                    pointerEvents: 'none',
                    zIndex: 10,
                }}
            />
        </div>
    );
};

/* ── Components ─────────────────────────────────────────── */

interface DataRowProps {
    label: string;
    children: ReactNode;
    highlight?: boolean;
    isLast?: boolean;
    isSurfaceLow?: boolean;
}

const DataRow: React.FC<DataRowProps> = ({ label, children, highlight = false, isLast = false, isSurfaceLow = false }) => (
    <div className={`flex items-center px-6 py-4 border-b border-slate-100 ${isSurfaceLow ? 'bg-[#f5f3f3]' : 'bg-white'} ${isLast ? 'border-none' : ''}`}>
        <div className="w-1/3 text-[10px] font-bold text-[#1b1c1c]/40 uppercase tracking-widest">
            {label}
        </div>
        <div className={`flex-1 text-xs font-medium ${highlight ? 'text-[#ba1a1a] font-bold' : 'text-[#003fb7]'} truncate`}>
            {children}
        </div>
    </div>
);

/* ── Main Application ─────────────────────────────────────────── */

export default function Apv() {
    const [scanData, setScanData] = useState<GraphData | null>(null);
    const [scannedNodes, setScannedNodes] = useState<string[]>([]);
    const [affectedNodes, setAffectedNodes] = useState<Set<string>>(new Set());
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch('/graph_report.json')
            .then(res => res.json())
            .then((raw: RawData) => {
                setScanData(processData(raw));
                setLoading(false);
            })
            .catch(err => {
                console.error("Failed to load Titan Knowledge Graph:", err);
                setLoading(false);
            });
    }, []);

    const calculateBlastRadius = useCallback((startNodeId: string) => {
        if (!scanData) return new Set<string>();
        const blast = new Set<string>();
        const queue = [startNodeId];
        while (queue.length > 0) {
            const curr = queue.shift()!;
            scanData.edges.filter(e => e.source === curr).forEach(e => {
                if (!blast.has(e.target)) {
                    blast.add(e.target);
                    queue.push(e.target);
                }
            });
        }
        return blast;
    }, [scanData]);

    useEffect(() => {
        if (!scanData) return;

        let index = 0;
        const nodeKeys = scanData.nodes.map(n => n.id);
        
        const interval = setInterval(() => {
            if (index >= nodeKeys.length) {
                clearInterval(interval);
                return;
            }
            const nextId = nodeKeys[index];
            setScannedNodes(prev => [...prev, nextId]);
            if (scanData.vulnerabilities[nextId]) {
                const blast = calculateBlastRadius(nextId);
                setAffectedNodes(prev => {
                    const next = new Set(prev);
                    blast.forEach(t => next.add(t));
                    return next;
                });
            }
            index++;
        }, 600);
        return () => clearInterval(interval);
    }, [scanData, calculateBlastRadius]);

    const nodeVulnerabilities = useMemo<VulnerabilityData[]>(() => {
        if (!selectedNode || !scanData) return [];
        return scanData.vulnerabilities[selectedNode.id] || [];
    }, [selectedNode, scanData]);

    if (loading || !scanData) return <div className="w-screen h-screen flex items-center justify-center bg-[#fbf9f8] text-[#1b1c1c] font-bold uppercase tracking-widest">Initializing Titan Engine...</div>;

    return (
        <div className="w-screen h-screen bg-[#fbf9f8] overflow-hidden font-sans text-slate-900 flex flex-col relative">
            {/* Header Legend */}
            <div className="h-16 px-10 flex items-center justify-between bg-white/60 backdrop-blur-xl z-30 shrink-0">
                <div className="flex items-center gap-4">
                    <div className="w-9 h-9 bg-[#003fb7] rounded-lg flex items-center justify-center shadow-lg shadow-blue-900/20">
                        <Shield className="w-5 h-5 text-white" />
                    </div>
                    <div>
                        <h1 className="text-sm font-bold tracking-[0.1em] uppercase text-[#1b1c1c]" style={{ fontFamily: 'Plus Jakarta Sans, sans-serif' }}>
                            Threat Propagation
                        </h1>
                    </div>
                </div>

                <div className="flex items-center gap-10">
                    <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-[#ba1a1a]" />
                        <span className="text-[10px] font-bold text-[#1b1c1c] uppercase tracking-widest">Threat Origin</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <Activity className="w-4 h-4 text-[#d97e1a]" />
                        <span className="text-[10px] font-bold text-[#1b1c1c] uppercase tracking-widest">Blast Zone</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-[#006d45]" />
                        <span className="text-[10px] font-bold text-[#1b1c1c] uppercase tracking-widest">Clean</span>
                    </div>
                </div>
            </div>

            {/* Stage */}
            <div className="flex-1 relative overflow-hidden bg-[#fbf9f8]">
                <div className="absolute inset-0 opacity-[0.04] pointer-events-none" style={{ backgroundImage: 'radial-gradient(#1b1c1c 1px, transparent 1px)', backgroundSize: '32px 32px' }}></div>
                <CanvasGraph 
                    data={scanData} 
                    scannedNodes={scannedNodes} 
                    affectedNodes={affectedNodes} 
                    onNodeClick={setSelectedNode}
                />
            </div>

            {/* Matrix Scan Detail Card */}
            {selectedNode && (
                <div className="absolute top-20 right-8 w-[360px] bg-white rounded-2xl shadow-[0_20px_40px_rgba(0,22,78,0.08)] z-40 overflow-hidden flex flex-col animate-in slide-in-from-right-4 duration-300 border border-slate-200/50">
                    {/* Header */}
                    <div className="p-6 bg-white flex items-center justify-between">
                        <h2 className="text-sm font-bold tracking-[0.05em] text-[#1b1c1c] uppercase" style={{ fontFamily: 'Plus Jakarta Sans, sans-serif' }}>
                            {selectedNode.label}
                        </h2>
                        <button 
                            onClick={() => setSelectedNode(null)}
                            className="p-1.5 hover:bg-[#f5f3f3] rounded-lg transition-all text-[#1b1c1c]/40"
                        >
                            <X className="w-4 h-4" />
                        </button>
                    </div>

                    {/* Data Table */}
                    <div className="flex flex-col">
                        <DataRow label="Source">
                            {selectedNode.fullPath}
                        </DataRow>
                        
                        <DataRow label="Type">
                            {nodeVulnerabilities.length > 0 ? nodeVulnerabilities[0].type : "Verified Clear"}
                        </DataRow>

                        <DataRow label="Position">
                            {nodeVulnerabilities.length > 0 ? `Line ${nodeVulnerabilities[0].line_number}` : "N/A"}
                        </DataRow>

                        <DataRow label="Impact" highlight={nodeVulnerabilities.length > 0}>
                            {nodeVulnerabilities.length > 0 ? "CRITICAL" : "STABLE"}
                        </DataRow>

                        <DataRow label="Status">
                            <div className="flex items-center gap-2">
                                <div className={`w-2 h-2 rounded-full ${nodeVulnerabilities.length > 0 ? 'bg-[#ba1a1a]' : 'bg-[#006d45]'}`}></div>
                                <span className="text-[#1b1c1c]">{nodeVulnerabilities.length > 0 ? 'Unpatched' : 'Clean'}</span>
                            </div>
                        </DataRow>

                        <DataRow label="Trace" isLast={true}>
                            {nodeVulnerabilities.length > 0 ? (
                                <code className="text-[10px] font-mono text-[#1b1c1c] block truncate" title={nodeVulnerabilities[0].snippet}>
                                    {nodeVulnerabilities[0].snippet}
                                </code>
                            ) : (
                                <span className="text-slate-400 italic">No threat data</span>
                            )}
                        </DataRow>
                    </div>
                </div>
            )}
            
            <style dangerouslySetInnerHTML={{__html: `
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@700;800&display=swap');
                body {
                    background-color: #fbf9f8;
                    color: #1b1c1c;
                    -webkit-font-smoothing: antialiased;
                }
            `}} />
        </div>
    );
}