# Airloom Telemetry Advanced Analyzer (AirloomDD)

This repository contains the complete reverse-engineering and visualization suite for decoding high-frequency binary `.pcap` telemetry streams into interactive mathematical plots and unified DataFrames.

## ⚙️ Core Architecture
The system dynamically decodes `.pcap` (and pre-parsed `.csv`) datalogger files using a flexible, dynamic Markdown-based dictionary system.
**Source of Truth:** The `ICD_Formats/` folder contains exactly defined byte-sizes, formats, and structural arrays indicating exactly how the raw binary payloads are mapped out. If the message payload structure changes, you only need to update the `.md` file—no code changes required!

## 🚀 Native Desktop Application

The `gui_telemetry.py` tool is a high-performance, native application designed to securely ingest **500MB+** `.pcap` files directly from your hard drive, completely bypassing internet upload bottlenecks.

### Native Execution (Mac / Linux)
1. Ensure your environment is set up:
   ```bash
   conda activate airloomdata
   python gui_telemetry.py
   ```
2. **Simplified Plotting Workflow**:
   *   **Load File**: Click "Open Massive .pcap or .csv".
   *   **Select Message**: Choose a message ID from the dropdown.
   *   **Select Columns**: Click the items in the "Available Columns" list. The plot area will update automatically!
   *   **Manual Plotting**: Use the **🚀 Plot / Refresh Selected** button if you want to explicitly refresh the view.

### Download Standalone Executable (Windows / Mac)
The pre-compiled standalone versions are available in the `dist/` folder:
*   **Mac (.app)**: Double-click to launch directly from MacOS.
*   **Windows (.exe)**: Double-click to launch on Windows (No Python installation required).

---

## 🛠️ Installation & Build Instructions

If you are a developer and want to modify the source code or rebuild the standalone apps:

### 1. Environment Setup
```bash
# Create the environment (if not already done)
conda create -n airloomdata python=3.13
conda activate airloomdata

# Install dependencies
pip install -r requirements.txt
pip install pyinstaller  # Required for building the app/exe
```

### 2. Rebuilding the Standalone Apps
To update the `.app` (Mac) or `.exe` (Windows) in the `dist/` folder after making code changes, run this command in your terminal/PowerShell:

```bash
pyinstaller AirloomTelemetry.spec --noconfirm
```

*Note: You must run this command on a Mac to build the `.app` and on a Windows machine to build the `.exe`.*

---

## 📊 Key Features
*   **Instant Reactive Plotting**: Zero-latency plotting logic that updates as you select variables.
*   **Massive File Support**: Handles huge binary streams using native C-style decoding.
*   **Traveler Filtering**: Automatically identifies and filters travelers dynamically.
*   **Unified Excel Export**: Click the export button to mathematically fold the entire telemetry stream into a multi-tabbed Excel dataset (perfectly handles 1M+ row limits).
