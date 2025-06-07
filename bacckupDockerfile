FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y libglib2.0-0 libsm6 libxext6 libxrender-dev python3-tk && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt ./

# Install Python dependencies globally
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code
COPY src/ /app/src

# Set up Streamlit config and secrets
RUN mkdir -p /root/.streamlit
COPY config.toml /root/.streamlit/config.toml


# Set environment variables for Streamlit
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ENABLE_CORS=false

# Define PYTHONPATH explicitly
ENV PYTHONPATH="/app/src"
# Expose the Streamlit port
EXPOSE 8501

# Run the Streamlit app
CMD ["streamlit", "run", "src/main.py", "--server.port=8501", "--server.enableCORS=false", "--server.enableXsrfProtection=false"]