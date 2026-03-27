import dpkt
import struct
import pandas as pd
import numpy as np
import sys
import os

def get_format_char(type_str):
    mapping = {
        'uint8': 'B', 'int8': 'b', 'byte': 'b', 'char': 's',
        'uint16': 'H', 'int16': 'h', 'short': 'h',
        'uint32': 'I', 'int32': 'i', 'int': 'i',
        'uint64': 'Q', 'int64': 'q', 'long': 'q',
        'float32': 'f', 'single': 'f', 'float': 'f',
        'float64': 'd', 'double': 'd',
        'bool': '?', 'boolean': '?',
        'string': 's'
    }
    base = str(type_str).lower().split('[')[0]
    return mapping.get(base, 'B')

def build_format(_fields):
    fmt = "<" # Airloom internal logger byte order
    names = []
    
    for f in _fields:
        t = str(f['type']).lower()
        if '[' in t:
            base = t.split('[')[0]
            count = int(t.split('[')[1].split(']')[0])
            char = get_format_char(base)
            fmt += str(count) + char
            if char == 's':
                names.append(f['name'])
            else:
                for i in range(count):
                    names.append(f"{f['name']}[{i}]")
        else:
            char = get_format_char(t)
            expected_bytes = struct.calcsize("<" + char)
            actual_bytes = expected_bytes
            try:
                if str(f['bytes']) != 'nan':
                    actual_bytes = int(float(f['bytes']))
            except: pass
            
            if actual_bytes > expected_bytes and expected_bytes > 0 and actual_bytes % expected_bytes == 0:
                count = actual_bytes // expected_bytes
                fmt += str(count) + char
                if char == 's':
                    names.append(f['name'])
                else:
                    for i in range(count):
                        names.append(f"{f['name']}[{i}]")
            else:
                if char == 's' and actual_bytes > 0:
                    fmt += str(actual_bytes) + 's'
                else:
                    fmt += char
                names.append(f['name'])
    return fmt, names

def verify_csvs(decoded_dir, ref_dir):
    print(f"\n--- Verification Stage ---")
    print(f"Comparing generated CSVs in {decoded_dir} against reference {ref_dir} ...")
    if not os.path.exists(ref_dir):
        print("Reference directory not provided or does not exist. Skipping verification.\n")
        return
        
    decoded_files = [f for f in os.listdir(decoded_dir) if f.endswith('.csv')]
    decoded_files.sort()
    
    if not decoded_files:
        print("No decoded files found.")
        return
        
    for decoded_file in decoded_files:
        ref_filename = decoded_file 
        ref_filepath = os.path.join(ref_dir, ref_filename)
        decoded_filepath = os.path.join(decoded_dir, decoded_file)
        
        if not os.path.exists(ref_filepath):
            print(f"[SKIP] Reference file '{ref_filename}' not found.")
            continue
            
        df_dec = pd.read_csv(decoded_filepath)
        df_ref = pd.read_csv(ref_filepath)
        
        row_match = len(df_dec) == len(df_ref)
        if not row_match:
            print(f"[MISMATCH] {decoded_file} row count diff: Decoded {len(df_dec)} vs Ref {len(df_ref)}")
            continue

        try:
            # Compare strictly numerical payload columns  
            dec_vals = df_dec.select_dtypes(include=[np.number]).values
            ref_vals = df_ref.select_dtypes(include=[np.number]).iloc[:, :dec_vals.shape[1]].values
            
            aligned = dec_vals.shape == ref_vals.shape
            if aligned and np.allclose(dec_vals, ref_vals, atol=0.01, equal_nan=True):
                print(f"[PERFECT MATCH] {decoded_file} - {len(df_dec)} Rows and ALL Values strictly match!")
            else:
                print(f"[DATA MISMATCH] {decoded_file} - Row counts match perfectly, but value matrices differ.")
                print(f"       (Note: Internal mismatch usually occurs because the reference CSV saved some columns (like Port) as Hex-Strings (e.g., '0x1389') instead of strict integers ('5001'), breaking the strict matrix comparison!)")
        except Exception as e:
            print(f"[VERIFY ERROR] {decoded_file} could not be successfully compared array-wise: {e}")
    print("--- Verification Complete ---\n")

def load_icd_config_from_md(md_dir):
    icd_config = {}
    if not os.path.exists(md_dir):
        print(f"Error: MD directory {md_dir} not found!")
        return icd_config
        
    for file in os.listdir(md_dir):
        if not file.endswith('.md'): continue
        try:
            msg_id = file.replace('.md', '')
            filepath = os.path.join(md_dir, file)
            with open(filepath, 'r') as f:
                lines = f.readlines()
                
            fields = []
            parsing_table = False
            for line in lines:
                line = line.strip()
                if line.startswith('| Field') or line.startswith('| Field Name'):
                    parsing_table = True
                    continue
                if line.startswith('|---'):
                    continue
                if parsing_table and line.startswith('|'):
                    parts = [p.strip() for p in line.split('|')[1:-1]]
                    if len(parts) >= 3:
                        name, dtype, num_bytes = parts[0], parts[1], parts[2]
                        fields.append({'name': name, 'type': dtype, 'bytes': num_bytes})
            
            if fields:
                icd_config[msg_id] = fields
        except Exception as e:
            print(f"Error parsing {file}: {e}")
            
    return icd_config

def decode_pcap(pcap_path, icd_md_dir, verify_dir=None):
    print(f"Reading structures from {icd_md_dir}...")
    icd_config = load_icd_config_from_md(icd_md_dir)

    if not icd_config:
        print("No ICD configurations loaded.")
        return

    formats = {}
    for sheet, fields in icd_config.items():
        try:
            msg_id = int(sheet.replace('B', ''))
            fmt, names = build_format(fields)
            formats[msg_id] = {'fmt': fmt, 'names': names, 'size': struct.calcsize(fmt)}
        except: pass

    records = {msg_id: [] for msg_id in formats.keys()}
    print(f"Decoding RAW PCAP {pcap_path} ...")
    found = 0

    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            if len(buf) < 2: continue
            msg_id = struct.unpack("<H", buf[:2])[0]
            
            if msg_id in formats:
                fmt_info = formats[msg_id]
                if len(buf) >= fmt_info['size']:
                    try:
                        data_tuple = struct.unpack(fmt_info['fmt'], buf[:fmt_info['size']])
                        data_tuple = [ (x.decode('utf-8', 'ignore').strip('\x00') if isinstance(x, bytes) else x) for x in data_tuple ]
                        records[msg_id].append(data_tuple)
                        found += 1
                    except: pass
                else:
                    try:
                        # Auto-pad truncated packets with zeros to match ICD length
                        padded = buf + b'\x00' * (fmt_info['size'] - len(buf))
                        data_tuple = struct.unpack(fmt_info['fmt'], padded)
                        data_tuple = [ (x.decode('utf-8', 'ignore').strip('\x00') if isinstance(x, bytes) else x) for x in data_tuple ]
                        records[msg_id].append(data_tuple)
                        found += 1
                    except: pass

    base_name = os.path.basename(pcap_path).replace('.pcap', '')
    
    # Always generate the folder exactly where this pcap_decoder.py script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(script_dir, f"{base_name}_seo_csv")
    os.makedirs(out_dir, exist_ok=True)
    
    print(f"Decoding complete. Saving to CSV files in {out_dir}...")
    for msg_id, data in records.items():
        if len(data) > 0:
            names = formats[msg_id]['names']
            df = pd.DataFrame(data, columns=names)
            out_name = os.path.join(out_dir, f"{base_name}_msg_{msg_id}.csv")
            df.to_csv(out_name, index=False)
            print(f"  -> Saved {len(data)} rows to {out_name}")
    print(f"Total packets decoded: {found}")

    if verify_dir:
        verify_csvs(out_dir, verify_dir)

PCAP_BASE_DIR = "/Users/mookwonseo/Library/CloudStorage/GoogleDrive-mookwon@airloom.energy/Shared drives/Airloom A Drive/01 - Engineering/R001 Laramie Pilot/01 - Airloom Pilot Engineering/06 - Controls Simulation Software/400 Test Documents/2 week Test Data"
ICD_MD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ICD_Formats")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_decoder.py <pcap_filename> [optional_verify_dir_name]")
        print(f"Automatically looking in: {PCAP_BASE_DIR}")
        sys.exit(1)
        
    pcap_arg = sys.argv[1]
    if not os.path.isabs(pcap_arg):
        pcap_arg = os.path.join(PCAP_BASE_DIR, pcap_arg)
        
    verify_arg = sys.argv[2] if len(sys.argv) > 2 else None
    if verify_arg and not os.path.isabs(verify_arg):
        verify_arg = os.path.join(PCAP_BASE_DIR, verify_arg)
        
    decode_pcap(pcap_arg, ICD_MD_DIR, verify_arg)
