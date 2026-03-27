import os
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

def main():
    st.set_page_config(page_title="Airloom Telemetry App", layout="wide")
    st.title("📊 Airloom Telemetry Interactive Dashboard")
    
    st.sidebar.header("1. Data Selection")
    
    # Option 1: Direct File Upload (Best for Streamlit Cloud & Google Drive)
    uploaded_file = st.sidebar.file_uploader("📥 Upload CSV directly from Google Drive", type=['csv'])
    
    df = None
    msg_id = "Custom"
    
    if uploaded_file is not None:
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
        
        # Use st.cache_data so we don't physically reload the giant CSV every time the user checks a box!
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
