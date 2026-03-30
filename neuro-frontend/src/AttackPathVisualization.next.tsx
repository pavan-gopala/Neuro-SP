import { useState, useEffect, useMemo, useRef, useCallback, type ReactNode } from 'react';
import {
    Shield, CheckCircle, Activity, ShieldAlert, X,
} from 'lucide-react';
import Graph from 'graphology';
import Sigma from 'sigma';
import forceAtlas2 from 'graphology-layout-forceatlas2';

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

interface LayoutPosition {
    x: number;
    y: number;
}

interface SigmaNodeAttributes {
    x: number;
    y: number;
    size: number;
    label: string;
    color: string;
}

interface CanvasGraphProps {
    data: GraphData;
    scannedNodes: string[];
    affectedNodes: Set<string>;
    onNodeClick: (node: GraphNode) => void;
}

interface DataRowProps {
    label: string;
    children: ReactNode;
    highlight?: boolean;
    isLast?: boolean;
    isSurfaceLow?: boolean;
}

const COLORS = {
    PRIMARY: '#003fb7',
    SECURE: '#008a58',
    CRITICAL: '#d91e4a',
    COMPROMISED: '#d97e1a',
    SURFACE: '#fbf9f8',
    SURFACE_LOW: '#f5f3f3',
    ON_SURFACE: '#1b1c1c',
    EDGE: '#e5e7eb',
};

const NODE_STYLE = {
    secure: { radius: 14, lineWidth: 3, color: COLORS.SECURE },
    affected: { radius: 14, lineWidth: 3, color: COLORS.COMPROMISED },
    critical: { radius: 16, lineWidth: 3.5, color: COLORS.CRITICAL },
    scannedBoost: 0.5,
};

const LAYOUT = {
    horizontalSpacing: 8,
    verticalSpacing: 5,
    layerBandWidth: 3,
    maxRowsPerBand: 11,
};

const getLayeredLayout = (rawData: RawData): Record<string, LayoutPosition> => {
    const nodeIds = Object.keys(rawData.nodes).sort((left, right) => left.localeCompare(right));
    const indegree = new Map<string, number>(nodeIds.map((id) => [id, 0]));
    const outgoing = new Map<string, string[]>(nodeIds.map((id) => [id, []]));
    const levelMap = new Map<string, number>(nodeIds.map((id) => [id, 0]));

    Object.entries(rawData.edges).forEach(([source, targets]) => {
        if (!outgoing.has(source)) {
            outgoing.set(source, []);
        }

        targets.forEach((target) => {
            outgoing.get(source)?.push(target);
            if (indegree.has(target)) {
                indegree.set(target, (indegree.get(target) ?? 0) + 1);
            }
        });
    });

    const queue = nodeIds.filter((id) => (indegree.get(id) ?? 0) === 0);
    const seen = new Set<string>();

    while (queue.length > 0) {
        const current = queue.shift();
        if (!current) continue;

        seen.add(current);
        const currentLevel = levelMap.get(current) ?? 0;

        (outgoing.get(current) ?? []).forEach((target) => {
            levelMap.set(target, Math.max(levelMap.get(target) ?? 0, currentLevel + 1));
            indegree.set(target, (indegree.get(target) ?? 0) - 1);

            if ((indegree.get(target) ?? 0) <= 0) {
                queue.push(target);
            }
        });
    }

    nodeIds.forEach((id) => {
        if (!seen.has(id)) {
            levelMap.set(id, Math.max(levelMap.get(id) ?? 0, rawData.nodes[id].in_degree ?? 0));
        }
    });

    const layers = new Map<number, string[]>();
    nodeIds.forEach((id) => {
        const level = levelMap.get(id) ?? 0;
        if (!layers.has(level)) {
            layers.set(level, []);
        }
        layers.get(level)?.push(id);
    });

    const sortedLayers = Array.from(layers.entries()).sort(([left], [right]) => left - right);
    const maxLevel = sortedLayers.length > 0 ? sortedLayers[sortedLayers.length - 1][0] : 0;
    const centerX = (maxLevel * LAYOUT.horizontalSpacing) / 2;
    const positions: Record<string, LayoutPosition> = {};

    sortedLayers.forEach(([level, ids]) => {
        const rowCount = Math.max(1, Math.min(LAYOUT.maxRowsPerBand, ids.length));
        const columnCount = Math.ceil(ids.length / rowCount);
        const centerY = ((rowCount - 1) * LAYOUT.verticalSpacing) / 2;

        ids.forEach((id, index) => {
            const column = Math.floor(index / rowCount);
            const row = index % rowCount;
            const columnOffset =
                columnCount === 1
                    ? 0
                    : ((column / (columnCount - 1)) - 0.5) * LAYOUT.layerBandWidth;

            positions[id] = {
                x: level * LAYOUT.horizontalSpacing + columnOffset - centerX,
                y: row * LAYOUT.verticalSpacing - centerY,
            };
        });
    });

    return positions;
};

const processData = (rawData: RawData): GraphData => {
    const layout = getLayeredLayout(rawData);

    const nodes: GraphNode[] = Object.entries(rawData.nodes).map(([id, node]) => ({
        id,
        label: id.split('/').pop() || id,
        fullPath: id,
        lang: node.lang || 'unknown',
        x: layout[id]?.x ?? 0,
        y: layout[id]?.y ?? 0,
        isVulnerable: Boolean(rawData.vulnerabilities[id]?.length),
    }));

    const edges: GraphEdge[] = [];
    Object.entries(rawData.edges).forEach(([source, targets]) => {
        targets.forEach((target) => {
            edges.push({ source, target });
        });
    });

    return { nodes, edges, vulnerabilities: rawData.vulnerabilities };
};

const getNodeAppearance = (node: GraphNode, scannedNodes: string[], affectedNodes: Set<string>) => {
    const isCritical = node.isVulnerable;
    const isAffected = affectedNodes.has(node.id);
    const isScanned = scannedNodes.includes(node.id);

    if (isCritical) {
        return {
            radius: NODE_STYLE.critical.radius,
            lineWidth: NODE_STYLE.critical.lineWidth + (isScanned ? NODE_STYLE.scannedBoost : 0),
            color: NODE_STYLE.critical.color,
            showHackerIcon: true,
        };
    }

    if (isAffected) {
        return {
            radius: NODE_STYLE.affected.radius,
            lineWidth: NODE_STYLE.affected.lineWidth,
            color: NODE_STYLE.affected.color,
            showHackerIcon: false,
        };
    }

    return {
        radius: NODE_STYLE.secure.radius,
        lineWidth: NODE_STYLE.secure.lineWidth + (isScanned ? NODE_STYLE.scannedBoost : 0),
        color: NODE_STYLE.secure.color,
        showHackerIcon: false,
    };
};

const drawHackerIcon = (
    context: CanvasRenderingContext2D,
    x: number,
    y: number,
    color: string,
) => {
    context.save();
    context.translate(x, y);
    context.strokeStyle = color;
    context.fillStyle = color;
    context.lineWidth = 1.5;
    context.lineCap = 'round';
    context.lineJoin = 'round';

    context.beginPath();
    context.arc(0, -2.5, 3, 0, Math.PI * 2);
    context.stroke();

    context.beginPath();
    context.arc(0, 1.5, 7, Math.PI, 0);
    context.stroke();

    context.beginPath();
    context.moveTo(-5, 6);
    context.lineTo(5, 6);
    context.stroke();

    context.beginPath();
    context.moveTo(-1.25, -2.5);
    context.lineTo(-1.25, -2.5);
    context.moveTo(1.25, -2.5);
    context.lineTo(1.25, -2.5);
    context.stroke();

    context.restore();
};

const DataRow = ({ label, children, highlight = false, isLast = false, isSurfaceLow = false }: DataRowProps) => (
    <div className={`flex items-center px-6 py-4 border-b border-slate-100 ${isSurfaceLow ? 'bg-[#f5f3f3]' : 'bg-white'} ${isLast ? 'border-none' : ''}`}>
        <div className="w-1/3 text-[10px] font-bold text-[#1b1c1c]/40 uppercase tracking-widest">
            {label}
        </div>
        <div className={`flex-1 text-xs font-medium ${highlight ? 'text-[#ba1a1a] font-bold' : 'text-[#003fb7]'} truncate`}>
            {children}
        </div>
    </div>
);

const CanvasGraph = ({ data, scannedNodes, affectedNodes, onNodeClick }: CanvasGraphProps) => {
    const containerRef = useRef<HTMLDivElement | null>(null);
    const overlayCanvasRef = useRef<HTMLCanvasElement | null>(null);
    const sigmaRef = useRef<Sigma<SigmaNodeAttributes> | null>(null);
    const graphRef = useRef<Graph<SigmaNodeAttributes> | null>(null);
    const onNodeClickRef = useRef(onNodeClick);

    useEffect(() => {
        onNodeClickRef.current = onNodeClick;
    }, [onNodeClick]);

    const renderOverlay = useCallback(() => {
        const sigma = sigmaRef.current;
        const graph = graphRef.current;
        const overlayCanvas = overlayCanvasRef.current;
        if (!sigma || !graph || !overlayCanvas) return;

        const context = overlayCanvas.getContext('2d');
        if (!context) return;

        const rect = overlayCanvas.getBoundingClientRect();
        const pixelRatio = window.devicePixelRatio || 1;
        const width = Math.max(1, Math.round(rect.width * pixelRatio));
        const height = Math.max(1, Math.round(rect.height * pixelRatio));

        if (overlayCanvas.width !== width || overlayCanvas.height !== height) {
            overlayCanvas.width = width;
            overlayCanvas.height = height;
        }

        context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
        context.clearRect(0, 0, rect.width, rect.height);

        data.nodes.forEach((node) => {
            if (!graph.hasNode(node.id)) return;

            const attributes = graph.getNodeAttributes(node.id);
            const viewport = sigma.graphToViewport({ x: attributes.x, y: attributes.y });
            const appearance = getNodeAppearance(node, scannedNodes, affectedNodes);

            if (
                viewport.x < -appearance.radius - 20 ||
                viewport.y < -appearance.radius - 20 ||
                viewport.x > rect.width + appearance.radius + 20 ||
                viewport.y > rect.height + appearance.radius + 20
            ) {
                return;
            }

            context.save();
            context.strokeStyle = appearance.color;
            context.lineWidth = appearance.lineWidth;
            context.shadowColor = `${appearance.color}33`;
            context.shadowBlur = 10;
            context.beginPath();
            context.arc(viewport.x, viewport.y, appearance.radius, 0, Math.PI * 2);
            context.stroke();
            context.restore();

            if (appearance.showHackerIcon) {
                drawHackerIcon(context, viewport.x, viewport.y, appearance.color);
            }
        });
    }, [affectedNodes, data.nodes, scannedNodes]);

    useEffect(() => {
        if (!containerRef.current) return;

        const graph = new Graph<SigmaNodeAttributes>({ type: 'directed' });
        graphRef.current = graph;

        data.nodes.forEach((node) => {
            graph.addNode(node.id, {
                x: node.x,
                y: node.y,
                size: NODE_STYLE.secure.radius,
                label: node.label,
                color: 'rgba(0, 0, 0, 0)',
            });
        });

        data.edges.forEach((edge) => {
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
        });

        forceAtlas2.assign(graph, {
            iterations: 8,
            settings: {
                ...forceAtlas2.inferSettings(graph),
                gravity: 0.02,
                scalingRatio: 18,
                slowDown: 25,
            },
        });

        const sigma = new Sigma(graph, containerRef.current, {
            renderEdgeLabels: false,
            labelFont: 'Inter, sans-serif',
            labelSize: 12,
            labelColor: { color: COLORS.ON_SURFACE },
            defaultEdgeColor: COLORS.EDGE,
            defaultNodeColor: 'rgba(0, 0, 0, 0)',
            minCameraRatio: 0.3,
            maxCameraRatio: 3,
        });

        sigmaRef.current = sigma;

        const handleNodeClick = ({ node }: { node: string }) => {
            const clickedNode = data.nodes.find((item) => item.id === node);
            if (clickedNode) {
                onNodeClickRef.current(clickedNode);
            }
        };

        sigma.on('clickNode', handleNodeClick);
        sigma.on('afterRender', renderOverlay);
        sigma.on('resize', renderOverlay);
        sigma.refresh();
        renderOverlay();

        return () => {
            sigma.off('clickNode', handleNodeClick);
            sigma.off('afterRender', renderOverlay);
            sigma.off('resize', renderOverlay);
            sigma.kill();
            sigmaRef.current = null;
            graphRef.current = null;
        };
    }, [data, renderOverlay]);

    useEffect(() => {
        const sigma = sigmaRef.current;
        const graph = graphRef.current;
        if (!sigma || !graph) return;

        data.nodes.forEach((node) => {
            if (!graph.hasNode(node.id)) return;

            const appearance = getNodeAppearance(node, scannedNodes, affectedNodes);
            graph.setNodeAttribute(node.id, 'size', appearance.radius);
            graph.setNodeAttribute(node.id, 'color', 'rgba(0, 0, 0, 0)');
        });

        data.edges.forEach((edge) => {
            if (!graph.hasDirectedEdge(edge.source, edge.target)) return;

            const edgeKey = graph.directedEdge(edge.source, edge.target);
            if (edgeKey === undefined) return;

            const isActive = scannedNodes.includes(edge.source) && affectedNodes.has(edge.target);
            graph.setEdgeAttribute(edgeKey, 'color', isActive ? COLORS.COMPROMISED : COLORS.EDGE);
            graph.setEdgeAttribute(edgeKey, 'size', isActive ? 2.5 : 1);
        });

        sigma.refresh();
        renderOverlay();
    }, [affectedNodes, data, renderOverlay, scannedNodes]);

    return (
        <div className="absolute inset-0">
            <div
                ref={containerRef}
                style={{ position: 'absolute', inset: 0, background: 'transparent' }}
            />
            <canvas
                ref={overlayCanvasRef}
                className="absolute inset-0 pointer-events-none"
            />
        </div>
    );
};

export default function AttackPathVisualization() {
    const [scanData, setScanData] = useState<GraphData | null>(null);
    const [scannedNodes, setScannedNodes] = useState<string[]>([]);
    const [affectedNodes, setAffectedNodes] = useState<Set<string>>(new Set());
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch('/graph_report.json')
            .then((response) => response.json())
            .then((raw: RawData) => {
                setScanData(processData(raw));
                setLoading(false);
            })
            .catch((error) => {
                console.error('Failed to load Titan Knowledge Graph:', error);
                setLoading(false);
            });
    }, []);

    const calculateBlastRadius = useCallback((startNodeId: string) => {
        if (!scanData) return new Set<string>();

        const blast = new Set<string>();
        const queue: string[] = [startNodeId];

        while (queue.length > 0) {
            const current = queue.shift();
            if (!current) continue;

            scanData.edges
                .filter((edge) => edge.source === current)
                .forEach((edge) => {
                    if (!blast.has(edge.target)) {
                        blast.add(edge.target);
                        queue.push(edge.target);
                    }
                });
        }

        return blast;
    }, [scanData]);

    useEffect(() => {
        if (!scanData) return;

        let index = 0;
        const nodeIds = scanData.nodes.map((node) => node.id);

        const interval = setInterval(() => {
            if (index >= nodeIds.length) {
                clearInterval(interval);
                return;
            }

            const nextId = nodeIds[index];
            setScannedNodes((previous) => [...previous, nextId]);

            if (scanData.vulnerabilities[nextId]) {
                const blast = calculateBlastRadius(nextId);
                setAffectedNodes((previous) => {
                    const next = new Set(previous);
                    blast.forEach((id) => next.add(id));
                    return next;
                });
            }

            index += 1;
        }, 600);

        return () => clearInterval(interval);
    }, [calculateBlastRadius, scanData]);

    const nodeVulnerabilities = useMemo<VulnerabilityData[]>(() => {
        if (!selectedNode || !scanData) return [];
        return scanData.vulnerabilities[selectedNode.id] || [];
    }, [scanData, selectedNode]);

    if (loading || !scanData) {
        return (
            <div className="w-screen h-screen flex items-center justify-center bg-[#fbf9f8] text-[#1b1c1c] font-bold uppercase tracking-widest">
                Initializing Titan Engine...
            </div>
        );
    }

    return (
        <div className="w-screen h-screen bg-[#fbf9f8] overflow-hidden font-sans text-slate-900 flex flex-col relative">
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

            <div className="flex-1 relative overflow-hidden bg-[#fbf9f8]">
                <div className="absolute inset-0 opacity-[0.04] pointer-events-none" style={{ backgroundImage: 'radial-gradient(#1b1c1c 1px, transparent 1px)', backgroundSize: '32px 32px' }} />
                <CanvasGraph
                    data={scanData}
                    scannedNodes={scannedNodes}
                    affectedNodes={affectedNodes}
                    onNodeClick={setSelectedNode}
                />
            </div>

            {selectedNode && (
                <div className="absolute top-20 right-8 w-[360px] bg-white rounded-2xl shadow-[0_20px_40px_rgba(0,22,78,0.08)] z-40 overflow-hidden flex flex-col animate-in slide-in-from-right-4 duration-300 border border-slate-200/50">
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

                    <div className="flex flex-col">
                        <DataRow label="Source">
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

                        <DataRow label="Status">
                            <div className="flex items-center gap-2">
                                <div className={`w-2 h-2 rounded-full ${nodeVulnerabilities.length > 0 ? 'bg-[#ba1a1a]' : 'bg-[#006d45]'}`} />
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

            <style dangerouslySetInnerHTML={{ __html: `
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@700;800&display=swap');

                body {
                    background-color: #fbf9f8;
                    color: #1b1c1c;
                    -webkit-font-smoothing: antialiased;
                }
            ` }}
            />
        </div>
    );
}
