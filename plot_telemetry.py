import os
import pandas as pd
import matplotlib.pyplot as plt

def main():
    print("=== Airloom Telemetry Plotter ===")
    
    # 1. Find CSV folders in the current directory
    csv_folders = [d for d in os.listdir('.') if os.path.isdir(d) and d.endswith('_csv')]
    
    if not csv_folders:
        print("No *_csv directories found in the current folder. Please run pcap_decoder.py first.")
        return
        
    print("\nAvailable Data Folders:")
    for i, folder in enumerate(csv_folders):
        print(f"[{i}] {folder}")
        
    folder_idx = input(f"\nSelect a folder (0-{len(csv_folders)-1}) [default=0]: ").strip()
    try:
        folder_idx = int(folder_idx) if folder_idx.isdigit() else 0
        target_folder = csv_folders[folder_idx]
    except IndexError:
        print("Invalid selection!")
        return
    
    # 2. Find available Msg IDs
    csv_files = [f for f in os.listdir(target_folder) if f.endswith('.csv') and '_msg_' in f]
    if not csv_files:
        print(f"\nNo *_msg_*.csv files found inside {target_folder}.")
        return
        
    available_msgs = []
    for f in csv_files:
        msg_id_part = f.split('_msg_')[-1].replace('.csv', '')
        available_msgs.append((msg_id_part, f))
        
    available_msgs.sort()
    
    print("\nAvailable Message IDs:")
    for m_id, f in available_msgs:
        print(f"- {m_id}")
        
    msg_id = input("\nEnter the msg_id you want to plot (e.g. 301): ").strip()
    
    target_file = None
    for m_id, f in available_msgs:
        if m_id == msg_id:
            target_file = os.path.join(target_folder, f)
            break
            
    if not target_file:
        print(f"Invalid MSG ID: {msg_id}. Exiting.")
        return
        
    # 3. Load File and List Columns
    print(f"\nLoading data from {target_file}...")
    df = pd.read_csv(target_file)
    
    print("\nAvailable Columns:")
    cols = list(df.columns)
    for i, col in enumerate(cols):
        print(f"[{i:02d}] {col}")
        
    col_input = input("\nEnter the column indices to plot, separated by commas (e.g. 16, 17): ").strip()
    
    cols_to_plot = []
    for part in col_input.split(','):
        part = part.strip()
        if part.isdigit() and int(part) < len(cols):
            cols_to_plot.append(cols[int(part)])
            
    if not cols_to_plot:
        print("\nNo valid columns selected. Exiting.")
        return
        
    # 4. Plot
    print(f"\nPlotting: {', '.join(cols_to_plot)}...")
    
    num_plots = len(cols_to_plot)
    fig, axes = plt.subplots(num_plots, 1, figsize=(12, 3 * num_plots), sharex=True)
    
    if num_plots == 1:
        axes = [axes]
        
    x_axis = df['MSG CNT'] if 'MSG CNT' in df.columns else df.index
    x_label = "MSG CNT" if 'MSG CNT' in df.columns else "Sequence Index"
    
    # Auto-downsample massive datasets so Matplotlib renders instantly 
    # (Since monitors only have ~2k pixels anyway, plotting 500k points is just wasted rendering time)
    step = max(1, len(df) // 10000)  # Caps resolution roughly at 10,000 points
    
    for i, col in enumerate(cols_to_plot):
        ax = axes[i]
        ax.plot(x_axis[::step], df[col][::step], label=col, alpha=0.8, color=f'C{i}')
        
        if i == 0:
            ax.set_title(f"Message {msg_id} Telemetry")
        if i == num_plots - 1:
            ax.set_xlabel(x_label)
            
        ax.set_ylabel(col)
        ax.legend(loc='best')
        ax.grid(True, linestyle="--", alpha=0.6)
        
    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    main()
