
# cpf_program Central Provident Fund in Singapore.
New CPF program that calculates Singapore retirement funds.

## Installation Steps

1. clone the repository
- cd <your dest folder>
- git clone https://github.com/antscrawling/cpf_program.git


### Windows
2. **Install Python**:
   - Download and install Python from the [official Python website]  (https://www.python.org/downloads/).
   - Ensure you check the box to add Python to your system's PATH during installation.

3. **Install Required Libraries**:
   - Open Command Prompt and navigate to the project directory:
     ```cmd
     cd path\to\cpf_program
     ```
   - Install the required Python libraries:
     ```cmd
     pip install -r requirements.txt
     ```

4. **Run the Program**:
   - Run the Streamlit app:
     ```cmd
     cd src && streamlit run main.py --server.headless true
     ```

---

### Mac
1. clone the repository
- cd <your dest folder>
- git clone https://github.com/antscrawling/cpf_program.git

2. **Install Python**:
   - macOS comes with Python pre-installed. However, it is recommended to install the latest version using [Homebrew](https://brew.sh/):
     ```bash
     brew install python
     ```

3. **Install Required Libraries**:
   - Open Terminal and navigate to the project directory:
     ```bash
     cd /path/to/newcpf_program
     ```
   - Install the required Python libraries:
     ```bash
     pip3 install -r requirements.txt
     ```

4. **Run the Program**:
   - Run the Streamlit app:
     ```bash
    cd src && streamlit run main.py --server.headless true
     ```

---

### Docker
1. clone the repository
- cd <your dest folder>
- git clone https://github.com/antscrawling/cpf_program.git

2. **Install Docker**:
   - Download and install Docker from the [official Docker website](https://www.docker.com/).

3. **Build the Docker Image**:
   - Open a terminal or command prompt and navigate to the project directory:
     ```bash
     cd /path/to/cpf_program
     ```
   - Build the Docker image:
     ```bash
     docker build -t <username>/cpf-program .t newcpf_program .
     ```

4. **Run the Docker Container**:
   - Run the container and expose the Streamlit app on port 8501:
     ```bash
     docker run -p 8501:8501 antscrawlingjay/cpf-program

     ```

5. **Access the Application**:
   - Open a web browser and go to:
     ```
     http://localhost:8501
     ```

---

## Application Features

1. **Configuration Editor**:
   - Allows users to edit CPF simulation parameters dynamically.
   - Supports editing numeric, string, and JSON-like nested structures.
   - Automatically converts flat configurations into nested dictionaries when saving.
   - Saves the updated configuration to `cpf_config.json` in the correct format.

2. **Run Simulation**:
   - Executes the CPF simulation script (`cpf_run_simulation_v8.py`) using the current configuration.
   - Displays the simulation output or errors directly in the Streamlit app.

3. **Generate CSV Report**:
   - Runs the report generation script (`cpf_build_reports_v1.py`) to create a detailed CPF report.
   - Displays success or error messages based on the script's execution.

4. **Run Analysis**:
   - Executes the CPF analysis script (`cpf_analysis_v1.py`) to analyze mismatches and calculate final balances.
   - Displays the analysis results or errors directly in the app.

5. **Download XML Report**:
   - Reads the contents of `cpf_report.csv` and converts it into an XML format.
   - Provides a "Download XML" button to download the XML file (`cpf_report.xml`).

6. **Exit Application**:
   - Provides an "EXIT" button to terminate the Streamlit app immediately.

---

### Notes
- Ensure you have the `requirements.txt` file in the project directory with all the necessary dependencies listed.
- For Docker, ensure the `Dockerfile` is properly configured to install dependencies and run the Streamlit app.
- Ensure all required scripts (`cpf_run_simulation_v8.py`, `cpf_build_reports_v1.py`, `cpf_analysis_v1.py`) and files (`cpf_report.csv`, `cpf_config.json`) are present in the `src` directory.

Let me know if you need further assistance!
'''











