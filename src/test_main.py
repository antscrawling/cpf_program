import streamlit as st
import subprocess
import json
from cpf_config_loader_v11 import CPFConfig
import os
from datetime import datetime, date
import sys
import webbrowser

PATH = os.path.dirname(os.path.abspath(__file__))  # Dynamically determine the src directory
SRC_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the src directory
CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')  # Full path to the config file
FLAT_FILENAME = os.path.join(SRC_DIR, 'test_config1.json')  # Full path to the flat config file
#DATABASE_NAME = os.path.join(SRC_DIR, 'cpf_simulation.db')  # Full path to the database file


st.set_page_config(page_title="CPF Simulation Setup", layout="wide")
st.title("🧾 CPF Simulation Configurator")

# Load the configuration
config = CPFConfig(CONFIG_FILENAME)
#
# Display the flat dictionary in the Streamlit app
st.subheader("🔧 Edit Parameters")
updated_config = {}

for key, value in config.data.items():
    if isinstance(value, (int, float)):
        updated_value = st.number_input(key, value=value)
    elif isinstance(value, str):
        updated_value = st.text_input(key, value=value)
    else:
        updated_value = st.text_area(key, value=json.dumps(value))
    updated_config[key] = updated_value



# Save the updated configuration
col1, col2, col3, col4, col5, col6  = st.columns(6)

with col1:
    if st.button("💾 Save"):
        
       # # Convert updated_config back to a nested dictionary
       # def unflatten_dict(d, sep="."):
       #     result = {}
       #     for k, v in d.items():
       #         keys = k.split(sep)
       #         current = result
       #         for key in keys[:-1]:
       #             current = current.setdefault(key, {})
       #         current[keys[-1]] = v
       #     return result
#
       # nested_config = unflatten_dict(updated_config)
#
       # # Save the updated configuration back to the file
       # for k, v in nested_config.items():
       #     if isinstance(v, (datetime, date)):
       #         nested_config[k] = v.strftime("%Y-%m-%d")  # Convert dates to strings
       #     elif isinstance(v, str):
       #         try:
       #             # Attempt to parse JSON strings back into dictionaries
       #             nested_config[k] = json.loads(v)
       #         except (json.JSONDecodeError, TypeError):
       #             # Keep as string if not valid JSON
       #             nested_config[k] = v

        # Save the updated configuration to a file
        with open(CONFIG_FILENAME, "w") as f:
            json.dump(config.data, f, indent=4)
        st.success("Configuration saved successfully!")
        
    
# Use the full path to the Python executable
python_executable = sys.executable  # This gets the current Python executable being used

with col2:
    if st.button("Run Simulation"):
        # Run the simulation script
        try:
            result = subprocess.run(
                [python_executable, os.path.join(PATH, "cpf_run_simulation_v9.py")],
                check=True,
                capture_output=True,
                text=True
            )
            # Save the simulation output to a temporary file
            simulation_output_path = os.path.join(SRC_DIR, "simulation_output.html")
            with open(simulation_output_path, "w") as f:
                f.write(f"<pre>{result.stdout}</pre>")

            # Open the simulation output in a new browser tab
            webbrowser.open_new_tab(f"file://{simulation_output_path}")
            
            # Generate a link to open the simulation output in a new tab
            simulation_url = f"file://{simulation_output_path}"
            st.success("Simulation completed! Click the link below to view the output:")
            st.markdown(f'<a href="{simulation_url}" target="_blank">Open Simulation Output</a>', unsafe_allow_html=True)
        except subprocess.CalledProcessError as e:
            st.error("Simulation failed:")
            st.code(e.stderr or str(e))

with col3:
    if st.button("🚀 Run CSV Report"):
        # Run the report generation script
        try:
            result = subprocess.run(
                [python_executable, os.path.join(PATH, "cpf_build_reports_v1.py")],
                check=True,
                capture_output=True,
                text=True
            )
            st.success("CSV Report generated successfully!")
            st.code(result.stdout)
        except subprocess.CalledProcessError as e:
            st.error("CSV Report generation failed:")
            st.code(e.stderr or str(e))

with col4:
    if st.button("📊 Run Analysis"):
        # Run the analysis script
        try:
            result = subprocess.run(
                [python_executable, os.path.join(PATH, "cpf_analysis_v1.py")],
                check=True,
                capture_output=True,
                text=True
            )
            st.success("Analysis completed successfully!")
            st.code(result.stdout)
        except subprocess.CalledProcessError as e:
            st.error("Analysis failed:")
            st.code(e.stderr or str(e))
        
with col5:
    import dicttoxml
    import pandas as pd

    # Read the contents of cpf_report.csv
    report_file_path = os.path.join(SRC_DIR, "cpf_report.csv")
    try:
        report_df = pd.read_csv(report_file_path)
        # Convert the DataFrame to a dictionary
        report_dict = report_df.to_dict(orient="records")
        # Convert the dictionary to XML
        xml_data = dicttoxml.dicttoxml(report_dict, custom_root="CPFReport", attr_type=False)
        # Provide the XML data for download
        st.download_button(
            label="Download XML",
            data=xml_data,
            file_name="cpf_report.xml",
            mime="application/xml",
        )
    except FileNotFoundError:
        st.error(f"File not found: {report_file_path}")
    except Exception as e:
        st.error(f"An error occurred while generating the XML: {e}")

with col6:
    if st.button(" EXIT "):
        # Forcefully exit the Streamlit app
        st.write("Exiting the application...")
        os._exit(0)


