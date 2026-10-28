# Use the official Azure Functions Python 3.12 base image
FROM mcr.microsoft.com/azure-functions/python:4-python3.12-appservice

# Install system dependencies required for PDF/A-4 conversion and .doc handling
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ghostscript \
        libreoffice \
        libmagic1 \
        poppler-utils && \
    rm -rf /var/lib/apt/lists/*

# Set working directory to the Function app root (default for the base image)
WORKDIR /home/site/wwwroot

# Copy the function app source code
COPY . /home/site/wwwroot

# Install Python dependencies (including Pillow, pypdf, python-magic)
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Expose the default Functions port (same as base image)
ENV AzureWebJobsScriptRoot=/home/site/wwwroot
ENV AzureFunctionsJobHost__functions__workerRuntime=python

# The base image already defines the entrypoint for Azure Functions.
