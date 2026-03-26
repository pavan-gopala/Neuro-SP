import React, { useState } from 'react';
import { BookOpen, Terminal, Shield, Menu, X, Copy, ChevronRight } from 'lucide-react';
import './HomePage.css';

// ==========================================
// 1. SCALABLE JSON DATA STORE
// ==========================================
const DOCS_DATA = [
  {
    category: "Overview",
    icon: <BookOpen size={18} />,
    items: [
      {
        id: "executive-summary",
        title: "1. Executive Summary",
        blocks: [
          { type: "p", content: "Neuro-SP Sentinel is a high-performance, distributed CLI and dashboard ecosystem designed to identify, validate, and neutralize 'Neural Leaks' within enterprise codebases." },
          { type: "note", content: "Moving beyond traditional, reactive static analysis, Neuro-SP acts as a Preemptive Defense System. It scans files for exposed tokens, hardcoded secrets, and adversarial vulnerabilities before they reach the management plane." }
        ]
      },
      {
        id: "capabilities-roadmap",
        title: "2. Current Capabilities & Roadmap",
        blocks: [
          { type: "p", content: "Our tool is designed to integrate seamlessly into a developer's workflow, catching exposures before they are committed." },
          { type: "list", items: [
            "Current State (v1.0 MVP): Targeted analysis of high-risk files (e.g., README.md).",
            "Future Roadmap: Deep-dive recursive directory scanning using Python's os.walk."
          ]}
        ]
      }
    ]
  },
  {
    category: "Technical Reference",
    icon: <Terminal size={18} />,
    items: [
      {
        id: "architecture",
        title: "3. Core Architecture",
        blocks: [
          { type: "p", content: "The system is built on a highly decoupled, three-tier microservices architecture to ensure maximum scalability and resilience." },
          { type: "table", headers: ["Layer", "Technology", "Port", "Role"], rows: [
            ["Visualization Plane", "React + Vite + D3.js", "5173", "High-contrast dashboard for analysts."],
            ["Management Plane", "Java Spring Boot", "8080", "Orchestrator and API Gateway."],
            ["Neural Engine", "Python FastAPI", "8000", "Asynchronous adversarial scanning agent."]
          ]}
        ]
      },
      {
        id: "getting-started",
        title: "4. Getting Started (Codespace)",
        blocks: [
          { type: "p", content: "Start the services in this specific order from the root directory. Ensure all ports are set to Public." },
          { type: "h3", content: "Step 1: Start the Neural Engine" },
          { type: "code", content: "uvicorn bridge:app --host 0.0.0.0 --port 8000 --reload" },
          { type: "h3", content: "Step 2: Start the Orchestrator" },
          { type: "code", content: "cd neuro-backend\n./mvnw spring-boot:run" }
        ]
      }
    ]
  }
];

// ==========================================
// 2. MAIN COMPONENT
// ==========================================
export default function HomePage() {
  const [activeId, setActiveId] = useState("executive-summary");
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  // Helper to find the currently active document
  const activeDoc = DOCS_DATA.flatMap(c => c.items).find(item => item.id === activeId);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert("Copied to clipboard!");
  };

  // Block Renderer Engine
  const renderBlock = (block: any, index: number) => {
    switch (block.type) {
      case 'p': return <p key={index} className="doc-p">{block.content}</p>;
      case 'h3': return <h3 key={index} className="doc-h3">{block.content}</h3>;
      case 'note': return (
        <div key={index} className="doc-note">
          <Shield size={20} className="note-icon" />
          <span>{block.content}</span>
        </div>
      );
      case 'code': return (
        <div key={index} className="doc-code-block">
          <div className="code-header">
            <span>Terminal</span>
            <button onClick={() => copyToClipboard(block.content)} className="copy-btn"><Copy size={14}/></button>
          </div>
          <pre><code>{block.content}</code></pre>
        </div>
      );
      case 'list': return (
        <ul key={index} className="doc-list">
          {block.items.map((item: string, i: number) => <li key={i}>{item}</li>)}
        </ul>
      );
      case 'table': return (
        <div key={index} className="table-wrapper">
          <table className="doc-table">
            <thead>
              <tr>{block.headers.map((h: string, i: number) => <th key={i}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {block.rows.map((row: string[], i: number) => (
                <tr key={i}>{row.map((cell, j) => <td key={j}>{cell}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      default: return null;
    }
  };

  return (
    <div className="docs-layout">
      {/* Mobile Toggle */}
      <button className="mobile-toggle" onClick={() => setIsMobileOpen(!isMobileOpen)}>
        {isMobileOpen ? <X size={24} /> : <Menu size={24} />}
      </button>

      {/* Sidebar Navigation */}
      <aside className={`docs-sidebar ${isMobileOpen ? 'open' : ''}`}>
        <div className="sidebar-brand">NEURO-SP</div>
        <nav className="sidebar-nav">
          {DOCS_DATA.map((category, idx) => (
            <div key={idx} className="nav-group">
              <div className="nav-category">
                {category.icon}
                <span>{category.category}</span>
              </div>
              <ul className="nav-items">
                {category.items.map(item => (
                  <li 
                    key={item.id} 
                    className={`nav-item ${activeId === item.id ? 'active' : ''}`}
                    onClick={() => { setActiveId(item.id); setIsMobileOpen(false); }}
                  >
                    {item.title}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </aside>

      {/* Main Content Area */}
      <main className="docs-main">
        <div className="content-container">
          <div className="breadcrumbs">
            <span>Documentation</span> <ChevronRight size={14} /> <span className="current-path">{activeDoc?.title}</span>
          </div>
          
          <h1 className="doc-title">{activeDoc?.title}</h1>
          
          <div className="doc-content">
            {activeDoc?.blocks.map((block, index) => renderBlock(block, index))}
          </div>
        </div>
      </main>
    </div>
  );
}