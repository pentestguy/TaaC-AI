# Use a lightweight python image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source code and template file
COPY TaaC-AI.py .
COPY template.html .

# Create a default output directory for reports
RUN mkdir /app/reports

# Set the entrypoint to the Python execution
ENTRYPOINT ["python", "TaaC-AI.py"]