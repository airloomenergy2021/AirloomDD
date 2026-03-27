import os
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

def main():
    st.set_page_config(page_title="Airloom Telemetry App", layout="wide")
    st.title("📊 Airloom Telemetry Interactive Dashboard")
    
    st.sidebar.header("1. Data Selection")
    
    # Option 1: Direct File Upload (Best for Streamlit Cloud & Google Drive)
    uploaded_file = st.sidebar.file_uploader("📥 Upload Raw .pcap or parsed .csv", type=['csv', 'pcap'])
    
    df = None
    msg_id = "Custom"
    
    @st.cache_data
    def decode_pcap_to_dataframes(file_buffer):
        import os, struct, dpkt
        from pcap_decoder import load_icd_config_from_md, build_format
        
        current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
        icd_md_dir = os.path.join(current_dir, "ICD_Formats")
        icd_config = load_icd_config_from_md(icd_md_dir)
        
        if not icd_config:
            raise ValueError("Local ICD missing")
            
        formats = {}
        for sheet, fields in icd_config.items():
            try:
                m_id = int(sheet.replace('B', ''))
                fmt, names = build_format(fields)
                formats[m_id] = {'fmt': fmt, 'names': names, 'size': struct.calcsize(fmt)}
            except Exception: pass
            
        records = {m_id: [] for m_id in formats.keys()}
        pcap = dpkt.pcap.Reader(file_buffer)
        
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
                
        dfs = {}
        for m_id, data in records.items():
            if data: dfs[str(m_id)] = pd.DataFrame(data, columns=formats[m_id]['names'])
        return dfs

    if uploaded_file is not None:
        if uploaded_file.name.endswith('.pcap'):
            try:
                with st.spinner(f"Decoding High-Frequency PCAP: {uploaded_file.name}..."):
                    all_dfs = decode_pcap_to_dataframes(uploaded_file)
                if not all_dfs:
                    st.error("No valid messages successfully unpacked from PCAP.")
                    return
                msg_id = st.sidebar.selectbox("Select Extracted Message ID", list(all_dfs.keys()))
                df = all_dfs[msg_id]
            except Exception as e:
                st.error(f"Failed to process PCAP file: {e}")
                return
        else:
            try:
                with st.spinner(f"Processing uploaded matrix: {uploaded_file.name}..."):
                    df = pd.read_csv(uploaded_file)
                msg_id = uploaded_file.name.split('_msg_')[-1].replace('.csv', '') if '_msg_' in uploaded_file.name else "Uploaded CSV"
            except Exception as e:
                st.error(f"Failed to read file: {e}")
                return
    else:
        # Option 2: Fallback to Local Directory Search if running locally
        st.sidebar.markdown("---")
        st.sidebar.caption("Or strictly select a local generated folder:")
        
        current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
        csv_folders = [d for d in os.listdir(current_dir) if os.path.isdir(os.path.join(current_dir, d)) and d.endswith('_csv')]
        csv_folders.sort()
        
        if not csv_folders:
            st.info("No local `_csv` folders detected. Please use the Drag & Drop File Uploader above!")
            return
            
        target_folder = st.sidebar.selectbox("Select a Local Data Folder", csv_folders)
        folder_path = os.path.join(current_dir, target_folder)
        csv_files = [f for f in os.listdir(folder_path) if f.endswith('.csv') and '_msg_' in f]
        
        if not csv_files:
            st.sidebar.warning(f"No *_msg_*.csv files found inside {target_folder}.")
            return
            
        available_msgs = []
        for f in csv_files:
            msg_id_part = f.split('_msg_')[-1].replace('.csv', '')
            available_msgs.append((msg_id_part, f))
        available_msgs.sort()
        
        msg_dict = {m_id: f for m_id, f in available_msgs}
        msg_id = st.sidebar.selectbox("Select a Message ID", list(msg_dict.keys()))
        
        target_file = os.path.join(folder_path, msg_dict[msg_id])
        
        @st.cache_data
        def load_data(filepath):
            return pd.read_csv(filepath)
            
        try:
            with st.spinner(f"Loading data matrix from {msg_dict[msg_id]}..."):
                df = load_data(target_file)
        except Exception as e:
            st.error(f"Failed to load {target_file}: {e}")
            return
        
    cols = list(df.columns)
    
    st.sidebar.header("2. Visualize")
    cols_to_plot = st.sidebar.multiselect("Select Columns to Plot", cols)
    
    if not cols_to_plot:
        st.info("👈 Please select at least one column from the sidebar to visualize.")
        st.write("### Data Preview")
        st.dataframe(df.head(1000), use_container_width=True)
        return
        
    # 4. Plot
    st.subheader(f"Message {msg_id} Telemetry Stack")
    
    num_plots = len(cols_to_plot)
    fig, axes = plt.subplots(num_plots, 1, figsize=(14, 3.5 * num_plots), sharex=True)
    if num_plots == 1:
        axes = [axes]
        
    x_axis = df['MSG CNT'] if 'MSG CNT' in df.columns else df.index
    x_label = "MSG CNT" if 'MSG CNT' in df.columns else "Sequence Index"
    
    with st.spinner("Rendering plots..."):
        for i, col in enumerate(cols_to_plot):
            ax = axes[i]
            
            # Draw the line
            ax.plot(x_axis, df[col], label=col, alpha=0.8, color=f'C{i}', linewidth=1.5)
            
            # Format aesthetics
            ax.set_ylabel(col, fontsize=10, fontweight='bold')
            ax.legend(loc='upper right')
            ax.grid(True, linestyle="--", alpha=0.6)
            
            # Remove top and right borders for a cleaner modern look
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            
            if i == num_plots - 1:
                ax.set_xlabel(x_label, fontsize=11, fontweight='bold')
                
        plt.tight_layout()
        st.pyplot(fig)

if __name__ == '__main__':
    main()
