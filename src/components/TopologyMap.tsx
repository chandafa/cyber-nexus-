// src/components/TopologyMap.tsx — SDD bagian 9.2 (Cytoscape.js).
import React, { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

interface Node {
  id: string;
  label: string;
  type?: string;
  role?: string;
}
interface Edge {
  source: string;
  target: string;
}

export const TopologyMap: React.FC<{ nodes: Node[]; edges: Edge[] }> = ({ nodes, edges }) => {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...nodes.map((n) => ({ data: { id: n.id, label: n.label, type: n.type || "host" } })),
        ...edges.map((e) => ({ data: { source: e.source, target: e.target } })),
      ],
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#7c5cff",
            label: "data(label)",
            color: "#e6e6f0",
            "font-size": "9px",
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 26,
            height: 26,
          },
        },
        {
          selector: 'node[type="router"]',
          style: { "background-color": "#00e0c6", width: 40, height: 40, "font-size": "11px" },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#2a2a4a",
            "curve-style": "bezier",
            "target-arrow-color": "#2a2a4a",
          },
        },
      ],
      layout: { name: "concentric", concentric: (n: any) => (n.data("type") === "router" ? 10 : 1), levelWidth: () => 1, minNodeSpacing: 40 },
    });
    cyRef.current = cy;
    return () => cy.destroy();
  }, [nodes, edges]);

  return (
    <div
      ref={ref}
      className="h-[440px] w-full rounded-xl border border-nexus-border bg-nexus-bg"
    />
  );
};
