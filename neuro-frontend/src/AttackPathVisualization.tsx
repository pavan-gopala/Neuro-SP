import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import type { ReactNode } from 'react';
import { Activity, ShieldAlert, X, Zap, Copy, Check, Eye, EyeOff, Type } from 'lucide-react';
import Graph from 'graphology';
import Sigma from 'sigma';
import forceAtlas2 from 'graphology-layout-forceatlas2';

/* ── Types ────────────────────────────────────────────────────── */

type Category = 'origin' | 'lateral' | 'deep' | 'clean';

interface VulnerabilityData {
    type: string;
    line_number: number;
    snippet: string;
}
interface RawNode { path: string; type: string; lang: string; is_entry?: boolean; in_degree: number; out_degree: number; }
interface RawData { nodes: Record<string, RawNode>; edges: Record<string, string[]>; vulnerabilities: Record<string, VulnerabilityData[]>; }
interface GraphNode { id: string; label: string; fullPath: string; lang?: string; x: number; y: number; vx: number; vy: number; ax: number; isVulnerable: boolean; }
interface GraphEdge { source: string; target: string; }
interface GraphData { nodes: GraphNode[]; edges: GraphEdge[]; vulnerabilities: Record<string, VulnerabilityData[]>; }
interface HoverChip { nodeId: string; label: string; x: number; y: number; category: Category; }

/* ── Category metadata ────────────────────────────────────────── */

const CATS: Category[] = ['origin', 'lateral', 'deep', 'clean'];

// ── Design System (Framework 1-2-3) ──────────────────────────────
// Framework 1: Threat Origin #D32F2F | Lateral Movement #E040FB
// Framework 2: Deep Blast nodes+edges #00BCD4 (dashed edges) | Crown Jewels #FF8C00
// Framework 3: Canvas #FBFAF5 | Clean nodes #007FC7 | Clean edges #E0E0E0
const CAT_META: Record<Category, { label: string; color: string; edgeColor: string; dashEdge?: boolean }> = {
    origin:  { label: 'Threat Origin',    color: '#D32F2F', edgeColor: '#E040FB' },
    lateral: { label: 'Lateral Movement', color: '#E040FB', edgeColor: '#E040FB' },
    deep:    { label: 'Deep Blast',       color: '#00BCD4', edgeColor: '#00BCD4', dashEdge: true },
    clean:   { label: 'Clean',            color: '#007FC7', edgeColor: '#E0E0E0' },
};

// FIX #5 — Node radii now encode severity hierarchy clearly
// Origin (critical) is significantly larger than clean (safe)
const R: Record<Category, number> = { origin: 13, lateral: 9, deep: 9, clean: 6 };

const SURFACE_BG = '#FBFAF5'; // Framework 3: canvas background
const EDGE_DEFAULT = '#E0E0E0'; // Framework 3: clean connections
const ON_SURFACE   = '#1b1c1c';

/* ── Data processing ──────────────────────────────────────────── */

const processData = (rawData: RawData): GraphData => {
    const nodes: GraphNode[] = Object.entries(rawData.nodes).map(([id, node]) => ({
        id, label: id.split('/').pop() || id, fullPath: id,
        lang: node.lang || 'unknown',
        x: Math.random() * 800 + 100, y: Math.random() * 600 + 100,
        vx: (Math.random() - 0.5) * 2, vy: 0, ax: 0,
        isVulnerable: !!rawData.vulnerabilities[id],
    }));
    const edges: GraphEdge[] = [];
    Object.entries(rawData.edges).forEach(([source, targets]) =>
        targets.forEach(target => edges.push({ source, target }))
    );
    return { nodes, edges, vulnerabilities: rawData.vulnerabilities };
};

/* ── Blast zone helpers ───────────────────────────────────────── */

function buildAdjacency(edges: GraphEdge[]) {
    const outMap = new Map<string, Set<string>>();
    const inMap  = new Map<string, Set<string>>();
    edges.forEach(({ source, target }) => {
        if (!outMap.has(source)) outMap.set(source, new Set());
        outMap.get(source)!.add(target);
        if (!inMap.has(target))  inMap.set(target, new Set());
        inMap.get(target)!.add(source);
    });
    return { outMap, inMap };
}

function bidirNeighbours(id: string, outMap: Map<string, Set<string>>, inMap: Map<string, Set<string>>) {
    const r = new Set<string>();
    outMap.get(id)?.forEach(n => r.add(n));
    inMap.get(id)?.forEach(n => r.add(n));
    return r;
}

function computeAllBlastZones(data: GraphData) {
    const originNodes  = new Set<string>(data.nodes.filter(n => n.isVulnerable).map(n => n.id));
    const { outMap, inMap } = buildAdjacency(data.edges);
    const lateralNodes = new Set<string>();
    const deepNodes    = new Set<string>();

    originNodes.forEach(id => bidirNeighbours(id, outMap, inMap).forEach(nb => {
        if (!originNodes.has(nb)) lateralNodes.add(nb);
    }));

    const visited = new Set([...originNodes, ...lateralNodes]);
    const queue   = [...lateralNodes];
    while (queue.length) {
        const curr = queue.shift()!;
        bidirNeighbours(curr, outMap, inMap).forEach(nb => {
            if (!visited.has(nb)) { visited.add(nb); deepNodes.add(nb); queue.push(nb); }
        });
    }
    return { originNodes, lateralNodes, deepNodes };
}

function getCategory(
    nodeId: string,
    originNodes: Set<string>, lateralNodes: Set<string>, deepNodes: Set<string>
): Category {
    if (originNodes.has(nodeId))  return 'origin';
    if (lateralNodes.has(nodeId)) return 'lateral';
    if (deepNodes.has(nodeId))    return 'deep';
    return 'clean';
}

/* ── Hex opacity helper ──────────────────────────────────────── */
// Appends a 2-digit hex alpha to a 6-digit hex color string
// Used to give blast edges 50% opacity so dense overlaps stay readable
function hexAlpha(hex: string, alpha: number): string {
    const a = Math.round(Math.max(0, Math.min(1, alpha)) * 255).toString(16).padStart(2, '0');
    return hex + a;
}

/* ── Edge color ──────────────────────────────────────────────── */
function edgeColor(
    src: Category, tgt: Category,
    visibleCats: Set<Category>
): { color: string; size: number } {
    const bothVisible = visibleCats.has(src) && visibleCats.has(tgt);
    if (!bothVisible) return { color: EDGE_DEFAULT, size: 1 };

    const isBlast = (c: Category) => c !== 'clean';
    if (!isBlast(src) && !isBlast(tgt)) return { color: EDGE_DEFAULT, size: 1 };

    // Deep blast edges: 60% opacity cyan — potential paths (dashed in overlay)
    if (src === 'deep' || tgt === 'deep') return { color: hexAlpha(CAT_META.deep.edgeColor, 0.6), size: 1.5 };
    // Lateral/origin edges: 80% opacity magenta — active, confirmed pivot paths
    return { color: hexAlpha(CAT_META.lateral.edgeColor, 0.8), size: 2 };
}

/* ── Hover Chip ────────────────────────────────────────────────── */

const HoverChipEl: React.FC<{ chip: HoverChip }> = ({ chip }) => {
    const meta  = CAT_META[chip.category];
    const chipW = 210, chipH = 58;
    const vw = window.innerWidth;
    let cx = chip.x + 16;
    let cy = chip.y - chipH - 12;
    if (cx + chipW > vw - 8) cx = chip.x - chipW - 16;
    if (cy < 72) cy = chip.y + 18;

    return (
        <div style={{ position: 'fixed', left: cx, top: cy, width: chipW, zIndex: 50, pointerEvents: 'none', animation: 'chipIn 110ms ease-out' }}>
            <div style={{ background: meta.color + '18', border: `1.5px solid ${meta.color}60`, borderRadius: 12, padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 4, boxShadow: '0 6px 20px rgba(0,0,0,0.14)', backdropFilter: 'blur(8px)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 7, height: 7, borderRadius: '50%', background: meta.color, flexShrink: 0 }} />
                    {/* FIX #1 — chip category label uses full-opacity color for legibility */}
                    <span style={{ fontSize: 9, fontWeight: 800, color: meta.color, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{meta.label}</span>
                </div>
                <span style={{ fontSize: 11, fontWeight: 600, color: ON_SURFACE, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: chipW - 28 }}>
                    {chip.label}
                </span>
            </div>
        </div>
    );
};

/* ── Sigma Graph Component ─────────────────────────────────────── */

interface CanvasGraphProps {
    data: GraphData;
    originNodes: Set<string>; lateralNodes: Set<string>; deepNodes: Set<string>;
    visibleCats: Set<Category>; labelCats: Set<Category>;
    onNodeClick: (node: GraphNode) => void;
    onHoverChip: (chip: HoverChip | null) => void;
}

const CanvasGraph: React.FC<CanvasGraphProps> = ({
    data, originNodes, lateralNodes, deepNodes,
    visibleCats, labelCats, onNodeClick, onHoverChip,
}) => {
    const containerRef   = useRef<HTMLDivElement>(null);
    const overlayRef     = useRef<HTMLCanvasElement>(null);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sigmaRef       = useRef<any>(null);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const graphRef       = useRef<any>(null);
    const onNodeClickRef = useRef(onNodeClick);
    const onHoverRef     = useRef(onHoverChip);
    const stateRef       = useRef({ originNodes, lateralNodes, deepNodes, visibleCats, labelCats, data });

    useEffect(() => { onNodeClickRef.current = onNodeClick; }, [onNodeClick]);
    useEffect(() => { onHoverRef.current = onHoverChip; },   [onHoverChip]);

    const applyFiltersAndColors = useCallback(() => {
        const graph = graphRef.current;
        const sigma = sigmaRef.current;
        if (!graph || !sigma) return;

        const { originNodes, lateralNodes, deepNodes, visibleCats, labelCats, data } = stateRef.current;

        graph.nodes().forEach((nodeId: string) => {
            const cat      = getCategory(nodeId, originNodes, lateralNodes, deepNodes);
            const visible  = visibleCats.has(cat);
            const showLbl  = visible && labelCats.has(cat);
            const origLbl  = graph.getNodeAttribute(nodeId, 'origLabel') as string;
            graph.setNodeAttribute(nodeId, 'hidden', !visible);
            graph.setNodeAttribute(nodeId, 'label',  showLbl ? origLbl : '');
        });

        data.edges.forEach(edge => {
            try {
                if (!graph.hasDirectedEdge(edge.source, edge.target)) return;
                const key = graph.directedEdge(edge.source, edge.target);
                if (key === undefined) return;
                const srcCat = getCategory(edge.source, originNodes, lateralNodes, deepNodes);
                const tgtCat = getCategory(edge.target, originNodes, lateralNodes, deepNodes);
                const { color, size } = edgeColor(srcCat, tgtCat, visibleCats);
                graph.setEdgeAttribute(key, 'color', color);
                graph.setEdgeAttribute(key, 'size',  size);
            } catch (_) {}
        });

        sigma.refresh();
    }, []);

    useEffect(() => {
        stateRef.current = { originNodes, lateralNodes, deepNodes, visibleCats, labelCats, data };
        applyFiltersAndColors();
    }, [originNodes, lateralNodes, deepNodes, visibleCats, labelCats, data, applyFiltersAndColors]);

    // FIX #2 — Overlay draws label halos so text stays readable through dense edges
    const drawOverlay = useCallback(() => {
        const canvas = overlayRef.current;
        const sigma  = sigmaRef.current;
        const graph  = graphRef.current;
        if (!canvas || !sigma || !graph) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        const { originNodes, lateralNodes, deepNodes, visibleCats, data } = stateRef.current;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.save();

        graph.nodes().forEach((nodeId: string) => {
            if (graph.getNodeAttribute(nodeId, 'hidden')) return;
            const attrs     = graph.getNodeAttributes(nodeId);
            const { x, y } = sigma.graphToViewport({ x: attrs.x, y: attrs.y });
            const cat       = getCategory(nodeId, originNodes, lateralNodes, deepNodes);
            const meta      = CAT_META[cat];
            const radius    = R[cat];
            const isOrigin  = cat === 'origin';

            // Node ring — nodes always at full 100% saturation per framework spec
            ctx.beginPath();
            ctx.arc(x, y, radius, 0, Math.PI * 2);
            // Origin: soft crimson fill tint so they stand apart even at small sizes
            ctx.fillStyle = isOrigin ? '#D32F2F18' : SURFACE_BG;
            ctx.fill();
            ctx.lineWidth   = isOrigin ? 3 : cat === 'lateral' ? 2.2 : 1.8;
            ctx.strokeStyle = meta.color; // full saturation, no alpha on node rings
            ctx.stroke();

            // Skull for origin nodes — rendered in full crimson
            if (isOrigin) {
                ctx.font         = `${Math.round(radius * 1.4)}px serif`;
                ctx.textAlign    = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle    = meta.color;
                ctx.fillText('☠', x, y);
            }

            // FIX #2 — Label halo: draw a solid background pill behind visible labels
            const label = attrs.label as string;
            if (label) {
                const fontSize   = 10;
                const fontStr    = `500 ${fontSize}px Inter, sans-serif`;
                ctx.font         = fontStr;
                const metrics    = ctx.measureText(label);
                const lw         = metrics.width;
                const lh         = fontSize + 4;
                const lx         = x - lw / 2;
                const ly         = y + radius + 6; // just below the node

                // White halo pill
                ctx.fillStyle    = 'rgba(251,250,245,0.93)';
                const pad = 3;
                ctx.beginPath();
                ctx.roundRect(lx - pad, ly - 2, lw + pad * 2, lh, 3);
                ctx.fill();

                // Label text
                ctx.fillStyle    = ON_SURFACE;
                ctx.textAlign    = 'center';
                ctx.textBaseline = 'top';
                ctx.fillText(label, x, ly);
            }
        });

        // ── Dashed edge overlay for deep blast paths ────────────────
        // Draw cyan dashed lines on top of Sigma's solid edges for deep blast
        // connections, indicating "potential" rather than "confirmed active" paths
        // data and visibleCats already destructured above from stateRef
        data.edges.forEach(edge => {
            const graph2 = graphRef.current;
            if (!graph2?.hasNode(edge.source) || !graph2?.hasNode(edge.target)) return;
            const srcCat = getCategory(edge.source, originNodes, lateralNodes, deepNodes);
            const tgtCat = getCategory(edge.target, originNodes, lateralNodes, deepNodes);
            if (srcCat !== 'deep' && tgtCat !== 'deep') return;
            if (!visibleCats.has(srcCat) || !visibleCats.has(tgtCat)) return;

            const sA = graph2.getNodeAttributes(edge.source);
            const tA = graph2.getNodeAttributes(edge.target);
            const sv = sigma.graphToViewport({ x: sA.x, y: sA.y });
            const tv = sigma.graphToViewport({ x: tA.x, y: tA.y });

            // Draw dashed cyan line on top of the solid one Sigma already drew
            ctx.beginPath();
            ctx.setLineDash([4, 4]);
            ctx.lineWidth   = 1;
            ctx.strokeStyle = '#00BCD499'; // 60% cyan
            ctx.moveTo(sv.x, sv.y);
            ctx.lineTo(tv.x, tv.y);
            ctx.stroke();
            ctx.setLineDash([]);
        });

        ctx.restore();
    }, []);

    // FIX #4 — After layout, fit camera to the bounding box of all nodes
    const fitCamera = useCallback(() => {
        const sigma = sigmaRef.current;
        const graph = graphRef.current;
        if (!sigma || !graph) return;

        // Collect bounding box in graph-space
        let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
        graph.nodes().forEach((nodeId: string) => {
            const { x, y } = graph.getNodeAttributes(nodeId);
            if (x < minX) minX = x;
            if (x > maxX) maxX = x;
            if (y < minY) minY = y;
            if (y > maxY) maxY = y;
        });
        if (!isFinite(minX)) return;

        // Graph-space center
        const cx = (minX + maxX) / 2;
        const cy = (minY + maxY) / 2;

        // Convert two extreme graph-space points to viewport to measure current pixel span
        const vpMin = sigma.graphToViewport({ x: minX, y: minY });
        const vpMax = sigma.graphToViewport({ x: maxX, y: maxY });
        const vpW   = Math.abs(vpMax.x - vpMin.x) || 1;
        const vpH   = Math.abs(vpMax.y - vpMin.y) || 1;

        const containerW = containerRef.current?.clientWidth  ?? 800;
        const containerH = containerRef.current?.clientHeight ?? 600;

        // Scale factor: how much do we need to zoom so the graph fills 80% of the container
        const scaleX = (containerW * 0.82) / vpW;
        const scaleY = (containerH * 0.82) / vpH;
        const scale  = Math.min(scaleX, scaleY);

        // Sigma camera ratio: higher = more zoomed OUT (more graph units visible)
        // Current ratio * (1/scale) gives the new ratio that fits the content
        const currentRatio = sigma.getCamera().ratio;
        const newRatio     = currentRatio / scale;

        sigma.getCamera().setState({ x: cx, y: cy, ratio: newRatio, angle: 0 });
    }, []);

    useEffect(() => {
        if (!containerRef.current) return;

        const graph = new Graph({ type: 'directed' });
        graphRef.current = graph;

        data.nodes.forEach(node => {
            const lbl = node.label;
            graph.addNode(node.id, {
                x: Math.random() * 20 - 10, y: Math.random() * 20 - 10,
                size: R.clean, label: lbl, origLabel: lbl, color: SURFACE_BG,
            });
        });

        data.edges.forEach(edge => {
            try {
                if (graph.hasNode(edge.source) && graph.hasNode(edge.target) &&
                    !graph.hasDirectedEdge(edge.source, edge.target)) {
                    graph.addDirectedEdge(edge.source, edge.target, { color: EDGE_DEFAULT, size: 1 });
                }
            } catch (_) {}
        });

        // Synchronous full layout
        forceAtlas2.assign(graph, {
            iterations: 600,
            settings: { ...forceAtlas2.inferSettings(graph), gravity: 0.5, scalingRatio: 18, slowDown: 1, barnesHutOptimize: graph.order > 60 },
        });

        // Minimum distance pass
        const nodeIds = graph.nodes();
        for (let pass = 0; pass < 40; pass++) {
            let moved = false;
            for (let i = 0; i < nodeIds.length; i++) {
                for (let j = i + 1; j < nodeIds.length; j++) {
                    const a  = graph.getNodeAttributes(nodeIds[i]);
                    const b  = graph.getNodeAttributes(nodeIds[j]);
                    const dx = b.x - a.x, dy = b.y - a.y;
                    const d  = Math.sqrt(dx * dx + dy * dy) || 0.001;
                    if (d < 4) {
                        const push = (4 - d) / 2 + 0.01;
                        const ux = (dx / d) * push, uy = (dy / d) * push;
                        graph.setNodeAttribute(nodeIds[i], 'x', a.x - ux);
                        graph.setNodeAttribute(nodeIds[i], 'y', a.y - uy);
                        graph.setNodeAttribute(nodeIds[j], 'x', b.x + ux);
                        graph.setNodeAttribute(nodeIds[j], 'y', b.y + uy);
                        moved = true;
                    }
                }
            }
            if (!moved) break;
        }

        const sigma = new Sigma(graph, containerRef.current, {
            renderEdgeLabels: false,
            renderLabels: false, // we draw our own halo labels in the canvas overlay
            labelFont: 'Inter, sans-serif', labelSize: 10, labelWeight: '500',
            labelColor: { color: ON_SURFACE },
            defaultEdgeColor: EDGE_DEFAULT, defaultNodeColor: SURFACE_BG,
            minCameraRatio: 0.15, maxCameraRatio: 4,
            // Tell Sigma to respect per-edge color attributes
            edgeReducer: (_, data) => ({ ...data, color: data.color ?? EDGE_DEFAULT }),
        });
        sigmaRef.current = sigma;

        sigma.on('clickNode', ({ node }: { node: string }) => {
            const nd = data.nodes.find(n => n.id === node);
            if (nd) onNodeClickRef.current(nd);
        });

        sigma.on('enterNode', ({ node, event }: { node: string; event: { original: MouseEvent | TouchEvent; x: number; y: number } }) => {
            const { originNodes, lateralNodes, deepNodes, data } = stateRef.current;
            const nd = data.nodes.find(n => n.id === node);
            if (!nd) return;
            const ev = event.original as MouseEvent;
            onHoverRef.current({
                nodeId: node, label: nd.label,
                x: ev.clientX ?? event.x, y: ev.clientY ?? event.y,
                category: getCategory(node, originNodes, lateralNodes, deepNodes),
            });
        });

        sigma.on('leaveNode', () => onHoverRef.current(null));

        const syncOverlay = () => {
            const ov = overlayRef.current, ct = containerRef.current;
            if (!ov || !ct) return;
            ov.width = ct.clientWidth; ov.height = ct.clientHeight;
            ov.style.width = ct.clientWidth + 'px'; ov.style.height = ct.clientHeight + 'px';
        };
        syncOverlay();

        // One-shot fit: on first afterRender (= first real paint) fit camera, then just draw overlay
        let didFit = false;
        sigma.on('afterRender', () => {
            drawOverlay();
            if (!didFit) {
                didFit = true;
                syncOverlay(); // refresh container dims before computing camera bounds
                fitCamera();
            }
        });

        // Apply initial filters — triggers first Sigma render → afterRender → fitCamera
        applyFiltersAndColors();

        const ro = new ResizeObserver(() => { syncOverlay(); sigma.refresh(); });
        ro.observe(containerRef.current);

        return () => { ro.disconnect(); sigma.kill(); };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [data, drawOverlay, applyFiltersAndColors, fitCamera]);

    return (
        <div ref={containerRef} style={{ position: 'absolute', inset: 0 }}>
            <canvas ref={overlayRef} style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 10 }} />
        </div>
    );
};

/* ── CopyButton ────────────────────────────────────────────────── */

const CopyButton: React.FC<{ text: string }> = ({ text }) => {
    const [copied, setCopied] = useState(false);
    const handleCopy = useCallback(() => {
        navigator.clipboard.writeText(text).then(() => {
            setCopied(true); setTimeout(() => setCopied(false), 1800);
        });
    }, [text]);
    return (
        <button onClick={handleCopy} title="Copy path" style={{ flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', width: 24, height: 24, borderRadius: 6, border: '1px solid #e5e7eb', background: copied ? '#f0fdf4' : '#f9fafb', cursor: 'pointer', transition: 'all 120ms', color: copied ? '#16a34a' : '#6b7280' }}>
            {copied ? <Check style={{ width: 12, height: 12 }} /> : <Copy style={{ width: 12, height: 12 }} />}
        </button>
    );
};

/* ── DataRow ───────────────────────────────────────────────────── */

interface DataRowProps {
    label: string; children: ReactNode;
    highlight?: boolean; isLast?: boolean; isSurfaceLow?: boolean;
    copyValue?: string; tooltip?: string;
}
const DataRow: React.FC<DataRowProps> = ({ label, children, highlight = false, isLast = false, isSurfaceLow = false, copyValue, tooltip }) => (
    <div className={`flex items-center px-6 py-4 border-b border-slate-100 ${isSurfaceLow ? 'bg-[#f5f3f3]' : 'bg-white'} ${isLast ? 'border-none' : ''}`}>
        <div className="w-1/3 text-[10px] font-bold text-[#1b1c1c]/50 uppercase tracking-widest shrink-0">{label}</div>
        <div className={`flex-1 text-xs font-medium ${highlight ? 'text-[#ba1a1a] font-bold' : 'text-[#003fb7]'} truncate min-w-0`} title={tooltip}>{children}</div>
        {copyValue && <div className="ml-2 shrink-0"><CopyButton text={copyValue} /></div>}
    </div>
);

/* ── Header filter chips ───────────────────────────────────────── */

// FIX #1 — VisChip: higher contrast text; active state uses full color, inactive uses slate-600 (not 400)
const VisChip: React.FC<{ cat: Category; active: boolean; onToggle: () => void }> = ({ cat, active, onToggle }) => {
    const { label, color } = CAT_META[cat];
    return (
        <button
            onClick={onToggle}
            title={`${active ? 'Hide' : 'Show'} ${label} nodes`}
            style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '5px 11px', borderRadius: 20,
                border: `1.5px solid ${active ? color + '70' : '#94a3b8'}`,
                background: active ? color + '12' : 'transparent',
                color: active ? color : '#475569',     // was #94a3b8 — now slate-600 for legibility
                opacity: active ? 1 : 0.75,            // was 0.55
                cursor: 'pointer', transition: 'all 150ms',
                fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase',
            }}
        >
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: active ? color : '#64748b', border: `1.5px solid ${active ? color : '#64748b'}`, flexShrink: 0 }} />
            {label}
            {active
                ? <Eye    style={{ width: 11, height: 11, marginLeft: 2 }} />
                : <EyeOff style={{ width: 11, height: 11, marginLeft: 2 }} />
            }
        </button>
    );
};

// FIX #1 — LabelChip: same contrast fix
const LabelChip: React.FC<{ cat: Category; active: boolean; onToggle: () => void }> = ({ cat, active, onToggle }) => {
    const { label, color } = CAT_META[cat];
    return (
        <button
            onClick={onToggle}
            title={`${active ? 'Hide' : 'Show'} labels for ${label}`}
            style={{
                display: 'flex', alignItems: 'center', gap: 4,
                padding: '4px 9px', borderRadius: 16,
                border: `1.5px solid ${active ? color + '55' : '#94a3b8'}`,
                background: active ? color + '0e' : 'transparent',
                color: active ? color : '#475569',     // was #94a3b8
                opacity: active ? 1 : 0.72,            // was 0.5
                cursor: 'pointer', transition: 'all 150ms',
                fontSize: 9, fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase',
            }}
        >
            <Type style={{ width: 9, height: 9 }} />
            {label.split(' ')[0]}
        </button>
    );
};

/* ── Legend ────────────────────────────────────────────────────── */
// FIX #3 — Explicit graph legend explaining node color AND edge color encoding
const GraphLegend: React.FC = () => (
    <div style={{
        position: 'absolute', bottom: 20, left: 20, zIndex: 30,
        background: 'rgba(251,249,248,0.94)', border: '1px solid #d4d4d0',
        borderRadius: 12, padding: '12px 16px', backdropFilter: 'blur(8px)',
        display: 'flex', flexDirection: 'column', gap: 10, minWidth: 196,
    }}>
        <span style={{ fontSize: 9, fontWeight: 800, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Legend</span>

        {/* Node sizes */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span style={{ fontSize: 9, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Nodes</span>
            {CATS.map(cat => (
                <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {/* FIX #5 — Show proportional circle sizes in legend */}
                    <div style={{ width: R[cat] * 2, height: R[cat] * 2, borderRadius: '50%', border: `${cat === 'origin' ? 2.5 : 1.5}px solid ${CAT_META[cat].color}`, background: SURFACE_BG, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: R[cat] < 9 ? 0 : 9 }}>
                        {cat === 'origin' ? <span style={{ fontSize: 9, lineHeight: 1 }}>☠</span> : null}
                    </div>
                    <span style={{ fontSize: 10, fontWeight: 600, color: CAT_META[cat].color }}>{CAT_META[cat].label}</span>
                </div>
            ))}
        </div>

        {/* Edge colors */}
        <div style={{ borderTop: '1px solid #e2e5ea', paddingTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span style={{ fontSize: 9, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Edges</span>
            {[
                { color: CAT_META.lateral.edgeColor, label: 'Origin / lateral path' },
                { color: CAT_META.deep.edgeColor,    label: 'Deep blast path' },
                { color: EDGE_DEFAULT,                label: 'Clean connection' },
            ].map(({ color, label }) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 22, height: 2.5, borderRadius: 2, background: color, flexShrink: 0 }} />
                    <span style={{ fontSize: 10, color: '#475569' }}>{label}</span>
                </div>
            ))}
        </div>
    </div>
);

/* ── Main Application ──────────────────────────────────────────── */

export default function App() {
    const [scanData,     setScanData]     = useState<GraphData | null>(null);
    const [originNodes,  setOriginNodes]  = useState<Set<string>>(new Set());
    const [lateralNodes, setLateralNodes] = useState<Set<string>>(new Set());
    const [deepNodes,    setDeepNodes]    = useState<Set<string>>(new Set());
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
    const [hoverChip,    setHoverChip]    = useState<HoverChip | null>(null);
    const [loading,      setLoading]      = useState(true);

    const [visibleCats, setVisibleCats] = useState<Set<Category>>(
        () => new Set<Category>(['origin', 'lateral', 'deep', 'clean'])
    );
    const [labelCats, setLabelCats] = useState<Set<Category>>(
        () => new Set<Category>(['origin', 'lateral', 'deep'])
    );

    const toggleVisible = useCallback((cat: Category) => {
        setVisibleCats(prev => { const n = new Set(prev); n.has(cat) ? n.delete(cat) : n.add(cat); return n; });
    }, []);
    const toggleLabel = useCallback((cat: Category) => {
        setLabelCats(prev => { const n = new Set(prev); n.has(cat) ? n.delete(cat) : n.add(cat); return n; });
    }, []);

    useEffect(() => {
        fetch('/graph_report.json')
            .then(r => r.json())
            .then((raw: RawData) => {
                const data = processData(raw);
                const { originNodes, lateralNodes, deepNodes } = computeAllBlastZones(data);
                setScanData(data);
                setOriginNodes(originNodes);
                setLateralNodes(lateralNodes);
                setDeepNodes(deepNodes);
                setLoading(false);
            })
            .catch(err => { console.error(err); setLoading(false); });
    }, []);

    const nodeVulnerabilities = useMemo<VulnerabilityData[]>(() => {
        if (!selectedNode || !scanData) return [];
        return scanData.vulnerabilities[selectedNode.id] || [];
    }, [selectedNode, scanData]);

    if (loading || !scanData) return (
        <div className="w-screen h-screen flex items-center justify-center bg-[#FBFAF5] text-[#1b1c1c] font-bold uppercase tracking-widest">
            Initializing Neuro Threat Engine...
        </div>
    );

    return (
        <div className="w-screen h-screen bg-[#FBFAF5] overflow-hidden font-sans text-slate-900 flex flex-col relative">

            {/* ── Header ── */}
            {/* FIX #1 — Header uses a slightly more opaque backdrop for better contrast */}
            <div className="px-8 flex items-center justify-between bg-white/90 backdrop-blur-xl z-30 shrink-0 border-b border-slate-200" style={{ minHeight: 64 }}>
                {/* Logo */}
                <div className="flex items-center gap-3 shrink-0">
                    <div className="w-9 h-9"><img src="/neuro.svg" alt="Neuro" /></div>
                    <h1 className="text-sm font-bold tracking-[0.1em] uppercase text-[#1b1c1c]" style={{ fontFamily: 'Plus Jakarta Sans, sans-serif' }}>Macula</h1>
                </div>

                {/* Controls */}
                <div className="flex items-center gap-5 flex-wrap justify-end">

                    {/* ── Visibility toggles ── */}
                    <div className="flex items-center gap-1.5">
                        {/* FIX #1 — section labels are now slate-600 (was slate-400) */}
                        <span className="text-[9px] font-bold text-slate-600 uppercase tracking-widest mr-1 shrink-0">Nodes</span>
                        {CATS.map(cat => (
                            <VisChip key={cat} cat={cat} active={visibleCats.has(cat)} onToggle={() => toggleVisible(cat)} />
                        ))}
                    </div>

                    {/* Divider */}
                    <div className="w-px h-6 bg-slate-300 shrink-0" />

                    {/* ── Label toggles ── */}
                    <div className="flex items-center gap-1.5">
                        <span className="text-[9px] font-bold text-slate-600 uppercase tracking-widest mr-1 shrink-0">Labels</span>
                        {CATS.map(cat => (
                            <LabelChip key={cat} cat={cat} active={labelCats.has(cat)} onToggle={() => toggleLabel(cat)} />
                        ))}
                    </div>
                </div>
            </div>

            {/* ── Stage ── */}
            <div className="flex-1 relative overflow-hidden bg-[#FBFAF5]">
                <div className="absolute inset-0 opacity-[0.03] pointer-events-none"
                     style={{ backgroundImage: 'radial-gradient(#1b1c1c 1px, transparent 1px)', backgroundSize: '32px 32px' }} />
                <CanvasGraph
                    data={scanData}
                    originNodes={originNodes} lateralNodes={lateralNodes} deepNodes={deepNodes}
                    visibleCats={visibleCats} labelCats={labelCats}
                    onNodeClick={setSelectedNode} onHoverChip={setHoverChip}
                />
                {/* FIX #3 — Legend always visible in bottom-left corner */}
                <GraphLegend />
            </div>

            {/* ── Hover Chip ── */}
            {hoverChip && <HoverChipEl chip={hoverChip} />}

            {/* ── Detail Card ── */}
            {selectedNode && (
                <div className="absolute top-20 right-8 w-[360px] bg-white rounded-2xl shadow-[0_20px_40px_rgba(0,22,78,0.10)] z-40 overflow-hidden flex flex-col animate-in slide-in-from-right-4 duration-300 border border-slate-200">
                    <div className="px-6 pt-5 pb-4 bg-white flex items-center justify-between gap-3 border-b border-slate-100">
                        <h2 className="text-sm font-bold tracking-[0.05em] text-[#1b1c1c] uppercase truncate min-w-0" title={selectedNode.label} style={{ fontFamily: 'Plus Jakarta Sans, sans-serif' }}>
                            {selectedNode.label}
                        </h2>
                        <button onClick={() => setSelectedNode(null)} className="p-1.5 hover:bg-[#f5f3f3] rounded-lg transition-all text-[#1b1c1c]/50 shrink-0">
                            <X className="w-4 h-4" />
                        </button>
                    </div>

                    <div className="flex flex-col">
                        <DataRow label="Source" copyValue={selectedNode.fullPath} tooltip={selectedNode.fullPath}>
                            {selectedNode.fullPath}
                        </DataRow>
                        <DataRow label="Type">
                            {nodeVulnerabilities.length > 0 ? nodeVulnerabilities[0].type : 'Verified Clear'}
                        </DataRow>
                        <DataRow label="Position">
                            {nodeVulnerabilities.length > 0 ? `Line ${nodeVulnerabilities[0].line_number}` : 'N/A'}
                        </DataRow>
                        <DataRow label="Impact" highlight={nodeVulnerabilities.length > 0}>
                            {nodeVulnerabilities.length > 0 ? 'CRITICAL' : 'STABLE'}
                        </DataRow>

                        {(() => {
                            const cat  = getCategory(selectedNode.id, originNodes, lateralNodes, deepNodes);
                            const meta = CAT_META[cat];

                            if (cat === 'origin') {
                                // Confirmed compromised — show as a hard role fact
                                return (
                                    <DataRow label="Blast Role">
                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide"
                                            style={{ background: meta.color + '15', color: meta.color, border: `1.5px solid ${meta.color}45` }}>
                                            <ShieldAlert className="w-3 h-3" />
                                            Threat Origin
                                        </span>
                                    </DataRow>
                                );
                            }

                            if (cat === 'lateral') {
                                // Clean node adjacent to a threat — it's a potential pivot, not a confirmed attack
                                return (
                                    <DataRow label="Exposure Risk">
                                        <div className="flex flex-col gap-1">
                                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide w-fit"
                                                style={{ background: meta.color + '12', color: meta.color, border: `1.5px solid ${meta.color}40` }}>
                                                <Activity className="w-3 h-3" />
                                                Pivot Candidate
                                            </span>
                                            <span style={{ fontSize: 9, color: '#64748b', lineHeight: 1.4 }}>
                                                Adjacent to a compromised node. Not breached, but reachable in one hop.
                                            </span>
                                        </div>
                                    </DataRow>
                                );
                            }

                            if (cat === 'deep') {
                                // Clean node in the theoretical blast radius — secondary/tertiary reachability
                                return (
                                    <DataRow label="Exposure Risk">
                                        <div className="flex flex-col gap-1">
                                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide w-fit"
                                                style={{ background: meta.color + '12', color: meta.color, border: `1.5px solid ${meta.color}40` }}>
                                                <Zap className="w-3 h-3" />
                                                Containment Perimeter
                                            </span>
                                            <span style={{ fontSize: 9, color: '#64748b', lineHeight: 1.4 }}>
                                                Within theoretical blast radius. Currently clean — monitor for propagation.
                                            </span>
                                        </div>
                                    </DataRow>
                                );
                            }

                            return null;
                        })()}

                        <DataRow label="Status">
                            <div className="flex items-center gap-2">
                                <div className={`w-2 h-2 rounded-full`} style={{ background: nodeVulnerabilities.length > 0 ? '#D32F2F' : '#007FC7' }} />
                                <span className="text-[#1b1c1c]">{nodeVulnerabilities.length > 0 ? 'Unpatched' : 'Clean'}</span>
                            </div>
                        </DataRow>

                        <DataRow label="Trace" isLast tooltip={nodeVulnerabilities.length > 0 ? nodeVulnerabilities[0].snippet : undefined}>
                            {nodeVulnerabilities.length > 0
                                ? <code className="text-[10px] font-mono text-[#1b1c1c] block truncate">{nodeVulnerabilities[0].snippet}</code>
                                : <span className="text-slate-400 italic">No threat data</span>
                            }
                        </DataRow>
                    </div>
                </div>
            )}

            <style dangerouslySetInnerHTML={{__html: `
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@700;800&display=swap');
                body { background-color: #FBFAF5; color: #1b1c1c; -webkit-font-smoothing: antialiased; }
                @keyframes chipIn {
                    from { opacity: 0; transform: translateY(5px) scale(0.96); }
                    to   { opacity: 1; transform: translateY(0)   scale(1); }
                }
            `}} />
        </div>
    );
}