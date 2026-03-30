import os
import sys
import struct
import pandas as pd
import numpy as np
import dpkt
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Import the decoder logic directly from the module
try:
    from pcap_decoder import load_icd_config_from_md, build_format
except ImportError:
    pass # Managed dynamically

class TelemetryGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("⚡ Airloom Telemetry Advanced Analyzer")
        self.geometry("1400x800")
        
        self.all_dfs = {}
        self.current_df = None
        self.figure = None
        self.canvas = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Left Panel for Controls
        control_frame = ttk.Frame(self, width=300, padding=10)
        control_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        # Right Panel for Plot
        self.plot_frame = ttk.Frame(self, padding=10)
        self.plot_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Controls Header
        ttk.Label(control_frame, text="1. Secure Local Upload", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        ttk.Button(control_frame, text="📂 Open Massive .pcap or .csv", command=self.load_file).pack(fill=tk.X, pady=5)
        
        self.file_label = ttk.Label(control_frame, text="No active file loaded", wraplength=280)
        self.file_label.pack(anchor=tk.W, pady=5)
        
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Messages Dropdown
        ttk.Label(control_frame, text="2. Decoded Message ID", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        self.msg_combo = ttk.Combobox(control_frame, state="disabled")
        self.msg_combo.pack(fill=tk.X, pady=5)
        self.msg_combo.bind("<<ComboboxSelected>>", self.on_msg_select)
        
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Columns List Selection
        ttk.Label(control_frame, text="3. Structural Columns", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        self.cols_listbox = tk.Listbox(control_frame, selectmode=tk.MULTIPLE, height=20, exportselection=0)
        self.cols_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Graphical Scrollbar Attachment
        scrollbar = ttk.Scrollbar(self.cols_listbox, orient=tk.VERTICAL)
        scrollbar.config(command=self.cols_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.cols_listbox.config(yscrollcommand=scrollbar.set)
        
        ttk.Button(control_frame, text="🚀 Render Decimated Plot", command=self.plot_data).pack(fill=tk.X, pady=10)
        
    def load_file(self):
        filepath = filedialog.askopenfilename(
            title="Locate Airloom Data Payload",
            filetypes=(("PCAP and CSV Files", "*.pcap *.csv"), ("All Files", "*.*"))
        )
        if not filepath:
            return
            
        self.file_label.config(text=f"Loaded:\n{os.path.basename(filepath)}")
        self.update()
        
        if filepath.endswith(".pcap"):
            self.process_pcap(filepath)
        elif filepath.endswith(".csv"):
            self.process_csv(filepath)
            
    def process_csv(self, filepath):
        try:
            df = pd.read_csv(filepath)
            msg_id = os.path.basename(filepath).split('_msg_')[-1].replace('.csv', '') if '_msg_' in filepath else "CSV"
            self.all_dfs = {msg_id: df}
            self.update_msg_dropdown()
        except Exception as e:
            messagebox.showerror("Catastrophic Read Fail", f"Failed to mount CSV:\n{e}")
            
    def process_pcap(self, filepath):
        try:
            # Native path resolution to link back to the ICD Configurations
            current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
            icd_md_dir = os.path.join(current_dir, "ICD_Formats")
            
            from pcap_decoder import load_icd_config_from_md, build_format
            icd_config = load_icd_config_from_md(icd_md_dir)
            if not icd_config:
                messagebox.showerror("Fatal Missing Component", "No ICD configuration parsed from ICD_Formats folder.")
                return
                
            formats = {}
            for sheet, fields in icd_config.items():
                try:
                    m_id = int(sheet.replace('B', ''))
                    fmt, names = build_format(fields)
                    formats[m_id] = {'fmt': fmt, 'names': names, 'size': struct.calcsize(fmt)}
                except Exception: pass
                
            records = {m_id: [] for m_id in formats.keys()}
            
            with open(filepath, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    if len(buf) < 2: continue
                    try: m_id = struct.unpack("<H", buf[:2])[0]
                    except: continue
                    if m_id in formats:
                        fmt_info = formats[m_id]
                        padded = buf + b'\x00' * max(0, fmt_info['size'] - len(buf))
                        try:
                            data_tuple = struct.unpack(fmt_info['fmt'], padded[:fmt_info['size']])
                            data_tuple = [(x.decode('utf-8','ignore').strip('\x00') if isinstance(x,bytes) else x) for x in data_tuple]
                            records[m_id].append(data_tuple)
                        except: pass
                        
            self.all_dfs = {}
            for m_id, data in records.items():
                if data: 
                    self.all_dfs[str(m_id)] = pd.DataFrame(data, columns=formats[m_id]['names'])
                    
            if not self.all_dfs:
                messagebox.showwarning("Empty Stream", "No legitimate telemetry signatures detected in this PCAP container.")
                return
                
            self.update_msg_dropdown()
            
        except Exception as e:
            import traceback
            messagebox.showerror("Critical Parsing Error", f"Failure traversing binary PCAP tree:\n{traceback.format_exc()}")
            
    def update_msg_dropdown(self):
        msg_ids = list(self.all_dfs.keys())
        msg_ids.sort()
        self.msg_combo.config(values=msg_ids, state="readonly")
        self.msg_combo.current(0)
        self.on_msg_select(None)
        
    def on_msg_select(self, event):
        msg_id = self.msg_combo.get()
        self.current_df = self.all_dfs[msg_id]
        
        # Dynamically inject the listbox based on DataFrame dimensions
        self.cols_listbox.delete(0, tk.END)
        for col in self.current_df.columns:
            self.cols_listbox.insert(tk.END, col)
            
    def plot_data(self):
        if self.current_df is None:
            return
            
        selected_indices = self.cols_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("Selection Overridden", "You must select at least one geometric column from the middle panel to plot.")
            return
            
        cols_to_plot = [self.cols_listbox.get(i) for i in selected_indices]
        df = self.current_df
        
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
            
        # Natively destroy internal matplotlib rendering widgets to avoid memory leaks
        for widget in self.plot_frame.winfo_children():
            widget.destroy()
            
        num_plots = len(cols_to_plot)
        self.figure, axes = plt.subplots(num_plots, 1, figsize=(10, 3 * num_plots), sharex=True)
        if num_plots == 1:
            axes = [axes]
            
        x_axis = df['MSG CNT'] if 'MSG CNT' in df.columns else df.index
        x_label = "MSG CNT" if 'MSG CNT' in df.columns else "Sequence Index"
        
        # Extremely powerful decimation function ensures ~10,000 points perfectly mirror 1,000,000 row datasets without any computer freezing.
        step = max(1, len(df) // 10000)
        
        for i, col in enumerate(cols_to_plot):
            ax = axes[i]
            ax.plot(x_axis[::step], df[col][::step], label=col, alpha=0.8, color=f'C{i}', linewidth=1.5)
            ax.set_ylabel(col, fontsize=10, fontweight='bold')
            ax.legend(loc='upper right')
            ax.grid(True, linestyle="--", alpha=0.6)
            
            # Cleanly slice out top and right axis bounds
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            
            if i == num_plots - 1:
                ax.set_xlabel(x_label, fontsize=11, fontweight='bold')
                
        self.figure.tight_layout()
        
        # Integrate into the Tkinter window natively
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.plot_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # Inject standard zooming/panning toolbar provided by matplotlib
        toolbar = NavigationToolbar2Tk(self.canvas, self.plot_frame)
        toolbar.update()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

if __name__ == "__main__":
    app = TelemetryGUI()
    app.mainloop()
