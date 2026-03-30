# Airloom Telemetry Dashboard (AirloomDD)

This repository contains the complete reverse-engineering and visualization suite for decoding high-frequency binary `.pcap` telemetry streams into interactive mathematical plots and unified DataFrames.

## ⚙️ Core Architecture
The system dynamically decodes `.pcap` (and pre-parsed `.csv`) datalogger files using a flexible, dynamic Markdown-based dictionary system.
**Source of Truth:** The `ICD_Formats/` folder contains exactly defined byte-sizes, formats, and structural arrays indicating exactly how the raw binary payloads are mapped out. If the message payload structure changes, you only need to update the `.md` file—no code changes required!

## 🚀 The Two Tools

### 1. The Native Desktop Application (Recommended)
This is the fastest, most powerful native tool designed to effortlessly securely ingest **500MB+** `.pcap` files directly from your hard drive, completely bypassing internet slow-down.
*   **Run on Mac / Linux:** `python gui_telemetry.py`
*   **Run on Windows (No Python Required):** 
    1. Click the **Actions** tab at the top of this GitHub repository.
    2. Click the latest successful `Build Windows Application` workflow.
    3. Scroll to the bottom and download the `AirloomTelemetry-Windows-Executable` artifact.
    4. Unzip and run the completely standalone `.exe`!

**GUI Features:**
*   Instant loading speeds and dynamic decimation plotting logic.
*   **Traveler Filtering:** Automatically parses active travelers, allowing you to combine lines on a single plot or rigorously separate subplots dynamically.
*   **Excel Export Engine:** Click a single button to mathematically fold the entire loaded memory frame into a unified, multi-tabbed Excel `.xlsx` workbook perfectly sliced around Microsoft's 1-million row limit.

---

### 2. Headless Python CLI (`plot_telemetry.py` & `csv_to_excel.py`)
Standard terminal interfaces designed to sequentially crunch previously extracted `_csv` datastructures for rapid headless engineering tasks.
*   `python plot_telemetry.py` (For Matplotlib terminal dumps)
*   `python csv_to_excel.py` (For headless Excel folder conversions)

## 🛠️ Installation Requirements
If you are developing or running the software directly from Python (Mac), ensure you have the `airloomdata` environment configured:

```bash
conda create -n airloomdata python=3.10
conda activate airloomdata
pip install -r requirements.txt
```

*(Note: Only for the `.exe` or executable file, users can simply one-click the file, and it will be automatically installed and run the GUI program without requiring any Python dependencies!)*
