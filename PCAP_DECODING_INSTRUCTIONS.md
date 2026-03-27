# Airloom Controls Simulation PCAP Parser

This document outlines the process and requirements for parsing raw Airloom datalogger `.pcap` files back into human-readable CSV matrices for data analysis.

## Overview
The datalogger outputs packets in a format where raw binary payloads are stamped directly into the `.pcap` wrapper (Datalink Type Ethernet 1). Unlike standard network traces viewable in Wireshark, these packets do NOT contain Ethernet, IP, TCP, or UDP wrappers. 
Because the structure is custom and variable, the byte sequence sizes and types must be reconstructed dynamically using the **Interface Control Document (ICD)**.

## Requirements
Ensure you have the following pip dependencies installed:
```bash
python3 -m pip install pandas openpyxl dpkt numpy
```

## How to Prepare the Script
The parsing script (`pcap_decoder.py`) strictly relies on explicit Markdown Table definitions to map binary structures perfectly.
1. The script dynamically extracts configurations from your localized `ICD_Formats` folder.
2. Ensure you have populated `.md` files representing your target Message IDs (e.g., `ICD_Formats/301.md`, `ICD_Formats/312.md`).
3. Each markdown file MUST contain a single clean markdown table with `Field Name`, `Type`, and `Size (Bytes)` exactly reflecting your datalogger logic mapping.

## Execution
Run the script from your terminal, simply passing the target PCAP file name (it will automatically look for it inside your `2 week Test Data` Google Drive folder), and optionally a reference folder name if you wish to verify the data mathematically.

**Command Structure:**
```bash
python3 pcap_decoder.py <pcap_filename> [optional_verification_folder_name]
```

**Example:**
```bash
python3 pcap_decoder.py "20260325_211006_airlog.pcap"
```

## What the output looks like
The python execution will:
1. Parse your newly created `ICD_Formats/*.md` data dictionaries to establish structure arrays.
2. Iterate through millions of blocks inside the binary `.pcap` file dynamically buffering against the specific sizes you declared.
3. Automatically organize matches into internal tabular sets based on your verified structure offsets.
4. Export the resulting splits into a new folder named `[pcap_prefix]_seo_csv` created inside your **CURRENT WORKING DIRECTORY** (where you ran the script from), not the PCAP directory.

Example outputs created in your current directory:
- `20260325_204633_airlog_seo_csv/20260325_204633_airlog_msg_301.csv`
- `20260325_204633_airlog_seo_csv/20260325_204633_airlog_msg_302.csv`

## Optional Verification
If you pass a third argument pointing to a directory containing existing, officially parsed CSV files, the script will mathematically verify every numerical value in the newly generated matrix against the official outputs using `numpy.allclose()` to ensure exact data integrity.
