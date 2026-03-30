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
        
        # Traveler Selection
        ttk.Label(control_frame, text="3. Traveler Filter (Optional)", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        
        trv_frame = ttk.Frame(control_frame)
        trv_frame.pack(fill=tk.X, pady=2)
        
        self.traveler_listbox = tk.Listbox(trv_frame, selectmode=tk.MULTIPLE, height=4, exportselection=0)
        self.traveler_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add scrollbar to traveler
        trv_scroll = ttk.Scrollbar(trv_frame, orient=tk.VERTICAL)
        trv_scroll.config(command=self.traveler_listbox.yview)
        trv_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.traveler_listbox.config(yscrollcommand=trv_scroll.set)
        
        self.traveler_mode_combo = ttk.Combobox(control_frame, values=["Combine in Same Graph", "Separate Graphs"], state="readonly")
        self.traveler_mode_combo.current(0)
        self.traveler_mode_combo.pack(fill=tk.X, pady=2)
        
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

        # Columns List Selection
        ttk.Label(control_frame, text="4. Available Columns", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        self.cols_listbox = tk.Listbox(control_frame, selectmode=tk.EXTENDED, height=15, exportselection=0)
        self.cols_listbox.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # Binding selection to auto-plot
        self.cols_listbox.bind("<<ListboxSelect>>", lambda e: self.plot_data())
        
        # Graphical Scrollbar Attachment
        scrollbar1 = ttk.Scrollbar(self.cols_listbox, orient=tk.VERTICAL)
        scrollbar1.config(command=self.cols_listbox.yview)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        self.cols_listbox.config(yscrollcommand=scrollbar1.set)
        
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Action Button Area (Kept as manual refresh if needed)
        ttk.Button(control_frame, text="🔄 Refresh Plot", command=self.plot_data).pack(fill=tk.X, pady=10)
        
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Export Controls
        ttk.Label(control_frame, text="6. Data Export", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        ttk.Button(control_frame, text="📊 Export Full Stack to Excel", command=self.export_excel).pack(fill=tk.X, pady=5)
        
    def export_excel(self):
        if not self.all_dfs:
            messagebox.showwarning("No Payload Detected", "Secure a .pcap or .csv payload array first before attempting an Excel extraction!")
            return
            
        save_path = filedialog.asksaveasfilename(
            title="Export Unified Telemetry Excel Dataset",
            defaultextension=".xlsx",
            filetypes=[("Excel Workspace", "*.xlsx")]
        )
        if not save_path:
            return
            
        try:
            # Excel compilation is mechanically limited, so cap arrays at 1,048,575 rows logically
            with pd.ExcelWriter(save_path, engine='openpyxl') as writer:
                for msg_id, df in self.all_dfs.items():
                    safe_df = df.iloc[:1048575] if len(df) > 1048575 else df
                    safe_df.to_excel(writer, sheet_name=str(msg_id)[:31], index=False)
                    
            messagebox.showinfo("Export Successful", f"Compilation Complete!\n\nMechanically folded {len(self.all_dfs)} message structs into:\n{os.path.basename(save_path)}")
        except Exception as e:
            messagebox.showerror("Catastrophic Write Fail", f"Microsoft Excel serialization sequence collapsed:\n{e}")

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
            # Native path resolution structurally compatible with PyInstaller standard compilations
            if getattr(sys, 'frozen', False):
                # We are running as a PyInstaller executable bundle. Access internal hidden payload:
                base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
            else:
                # We are running conventionally via raw python
                base_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
                
            icd_md_dir = os.path.join(base_dir, "ICD_Formats")
            
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
        
        print(f"[*] Message {msg_id} selected. Updating column list...")
        
        # Dynamically inject the listbox based on DataFrame dimensions
        self.cols_listbox.delete(0, tk.END)
        for col in self.current_df.columns:
            self.cols_listbox.insert(tk.END, col)
            
        self.traveler_col_name = None
        for c in self.current_df.columns:
            if "traveler" in str(c).lower() and "num" in str(c).lower():
                self.traveler_col_name = c
                break
                
        self.traveler_listbox.config(state=tk.NORMAL)
        self.traveler_listbox.delete(0, tk.END)
        if self.traveler_col_name:
            unique_trvs = sorted(self.current_df[self.traveler_col_name].dropna().unique())
            for t in unique_trvs:
                self.traveler_listbox.insert(tk.END, f"Traveler {int(t)}")
        else:
            self.traveler_listbox.insert(tk.END, "N/A (No Traveler Data)")
            self.traveler_listbox.config(state=tk.DISABLED)
            
        # In the new simplified UI, clearing columns clears the plot
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
            for widget in self.plot_frame.winfo_children(): widget.destroy()
            self.canvas = None
            if self.figure: plt.close(self.figure)

    def plot_data(self):
        if self.current_df is None:
            return
            
        sel_indices = self.cols_listbox.curselection()
        cols_to_plot = [self.cols_listbox.get(i) for i in sel_indices]
        
        if not cols_to_plot:
            if self.canvas:
                self.canvas.get_tk_widget().destroy()
                for widget in self.plot_frame.winfo_children(): widget.destroy()
                self.canvas = None
            return
            
        print(f"[*] Plotting sequence triggered: {len(cols_to_plot)} columns...")
            
        df = self.current_df
        
        # Natively destroy internal matplotlib rendering widgets to avoid memory leaks
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
            self.canvas = None
        
        if self.figure:
            plt.close(self.figure)
            
        for widget in self.plot_frame.winfo_children():
            widget.destroy()
            
        selected_trvs = []
        if getattr(self, 'traveler_col_name', None) and str(self.traveler_listbox.cget("state")) == str(tk.NORMAL):
            sel_idx = self.traveler_listbox.curselection()
            if sel_idx:
                unique_trvs = sorted(self.current_df[self.traveler_col_name].dropna().unique())
                selected_trvs = [unique_trvs[i] for i in sel_idx]

        mode = getattr(self, 'traveler_mode_combo', None)
        mode_val = mode.get() if mode else ""
        
        plot_configs = [] 
        
        x_col = 'MSG CNT' if 'MSG CNT' in df.columns else df.index
        x_label = "MSG CNT" if 'MSG CNT' in df.columns else "Sequence Index"
        
        if not selected_trvs:
            for col in cols_to_plot:
                plot_configs.append((col, col, [(df[x_col], df[col], col, 0)]))
        else:
            if "Combine" in mode_val:
                for col in cols_to_plot:
                    series = []
                    for c_idx, t in enumerate(selected_trvs):
                        t_df = df[df[self.traveler_col_name] == t]
                        if len(t_df) > 0:
                            series.append((t_df[x_col], t_df[col], f"Trv {int(t)}", c_idx))
                    if series:
                        plot_configs.append((f"{col} (Combined Travelers)", col, series))
            else:
                for col in cols_to_plot:
                    for c_idx, t in enumerate(selected_trvs):
                        t_df = df[df[self.traveler_col_name] == t]
                        if len(t_df) > 0:
                            series = [(t_df[x_col], t_df[col], f"Trv {int(t)}", c_idx)]
                            plot_configs.append((f"{col} - Traveler {int(t)}", col, series))
                            
        num_plots = len(plot_configs)
        if num_plots == 0:
            return
            
        self.figure, axes = plt.subplots(num_plots, 1, figsize=(10, 3 * num_plots), sharex=True)
        if num_plots == 1:
            axes = [axes]
            
        for i, config in enumerate(plot_configs):
            title, ylabel, series = config
            ax = axes[i]
            
            for (x_vals, y_vals, label, color_idx) in series:
                step = max(1, len(x_vals) // 10000)
                if step == 0:
                    step = 1
                try:
                    ax.plot(x_vals[::step], y_vals[::step], label=label, alpha=0.8, color=f'C{color_idx}', linewidth=1.5)
                except Exception:
                    pass
                
            ax.set_ylabel(ylabel, fontsize=9, fontweight='bold')
            ax.set_title(title, fontsize=10, pad=3)
            ax.legend(loc='upper right', fontsize=8)
            ax.grid(True, linestyle="--", alpha=0.6)
            
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            
            if i == num_plots - 1:
                ax.set_xlabel(x_label, fontsize=10, fontweight='bold')
                
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
