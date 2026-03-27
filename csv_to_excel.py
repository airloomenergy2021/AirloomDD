import os
import sys
import pandas as pd
import glob
import re

def main():
    print("=== Airloom CSV to Excel Converter ===\n")
    
    if len(sys.argv) > 1:
        target_folder = sys.argv[1]
    else:
        # Find all _csv folders in the current directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        csv_folders = [d for d in os.listdir(current_dir) if os.path.isdir(os.path.join(current_dir, d)) and d.endswith('_csv')]
        csv_folders.sort()
        
        if not csv_folders:
            print("No folders ending in '_csv' found in the current directory.")
            return
            
        print("Available Data Folders:")
        for idx, folder in enumerate(csv_folders):
            print(f"[{idx}] {folder}")
            
        folder_idx_str = input(f"\nSelect a folder to combine (0-{len(csv_folders)-1}) [default=0]: ").strip()
        folder_idx = 0
        if folder_idx_str.isdigit():
            folder_idx = int(folder_idx_str)
        if folder_idx < 0 or folder_idx >= len(csv_folders):
            print("Invalid selection.")
            return
            
        target_folder = os.path.join(current_dir, csv_folders[folder_idx])

    if not os.path.exists(target_folder):
        print(f"Folder not found: {target_folder}")
        sys.exit(1)

    # Find CSVs
    csv_files = glob.glob(os.path.join(target_folder, "*.csv"))
    if not csv_files:
        print(f"No CSV files found inside {target_folder}")
        sys.exit(1)
        
    base_name = os.path.basename(target_folder).replace('_seo_csv', '').replace('_csv', '')
    out_excel = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{base_name}_Combined.xlsx")
    
    print(f"\nFound {len(csv_files)} CSV files. Building Excel file -> {out_excel}")
    print("Note: Because some files contain hundreds of thousands of data points, saving to a unified Excel file may take several minutes to compute!\n")
    
    # Use pandas to write to Excel. Requires openpyxl installed.
    with pd.ExcelWriter(out_excel, engine='openpyxl') as writer:
        for csv_file in sorted(csv_files):
            filename = os.path.basename(csv_file)
            
            # Extract tab name, e.g. "20260325_211006_airlog_msg_301.csv" -> "301"
            match = re.search(r'msg_(\d+)', filename)
            if match:
                sheet_name = match.group(1)
            else:
                # fallback
                sheet_name = filename.replace('.csv', '')[:31] # Excel max sheet name length is 31 characters
            
            print(f"  -> Reading {filename} into Tab '{sheet_name}'...")
            try:
                df = pd.read_csv(csv_file)
                
                # Excel has a strict mathematical row limit of 1,048,576 rows per sheet.
                if len(df) > 1048575:
                    print(f"     [WARNING] {filename} has {len(df)} rows. Exceeds Excel's strict limit! Truncating bottom rows to 1,048,575.")
                    df = df.iloc[:1048575]
                    
                df.to_excel(writer, sheet_name=sheet_name, index=False)
            except Exception as e:
                print(f"     [ERROR] Failed to process {filename}: {e}")
                
    print(f"\nSuccessfully combined all CSVs into: {out_excel}")

if __name__ == "__main__":
    main()
