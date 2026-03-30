---

# 🧠 Neuro-Sovereign
### Privacy-First Security Intelligence. Local-Fast.

**Neuro-Sovereign** is local-first Security Intelligence platform. It empowers developers to manage their attack surface and security posture directly on their own hardware—ensuring total data privacy without the overhead of cloud-based subscriptions.

## ✨ Key Principles
* **Privacy by Design:** No accounts, no telemetry, and no data egress. Your code stays on your machine.
* **Zero Friction:** Designed for immediate utility. Run a scan in seconds without the need for complex cloud configurations.
* **Hardware Optimized:** Built to leverage local compute power, providing near-instant feedback for a smoother developer workflow.
* **Sovereign Control:** An independent alternative for organizations and individuals who require full ownership of their security data.

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have Python 3.8+ installed.

### 2. Installation
Clone the repository and install the core dependencies:
```powershell
pip install fastapi uvicorn starlette
pip install -e .
```

### 3. Running the Scan
Start the Neuro-Scan engine from the project root:
```powershell
python -m neuroscan.cli
```

---

## 🏗️ Project Structure
* **[neuroscan](https://github.com/pavan-gopala/Neuro-Sovereign/tree/master/neuroscan):** The core analysis and discovery engine.
* **[agents](https://github.com/pavan-gopala/Neuro-Sovereign/tree/master/agents):** Automated security logic and reporting modules.
* **[neuro-frontend](https://github.com/pavan-gopala/Neuro-Sovereign/tree/master/neuro-frontend):** A modern UI for visualizing threat models and asset relationships.

---

## 📈 Roadmap
- [x] **Core Discovery:** Local file system crawling and metadata extraction.
- [x] **Sentinel CLI:** A streamlined interface for local execution.
- [ ] **Enhanced Visualization:** Advanced graph-based reporting in the dashboard.
- [ ] **Cross-Platform Optimization:** Dedicated performance tuning for various hardware architectures.

---

## ⚖️ Licensing & Usage
**Neuro-Sovereign** is committed to the community.
* **For Individuals:** This project is Open Source and free to use for personal projects, research, and individual developers.
* **For Enterprises:** Commercial use (organizations with >X employees or $Y revenue) requires a commercial license. This ensures we can continue to build and maintain the "Sovereign Brain" for everyone.

Please contact the maintainers for enterprise licensing inquiries.
