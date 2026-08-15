FROM python:3.11-slim

WORKDIR /app

# Install git (required for cloning Git repositories)
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose app port 4003
EXPOSE 4003

ENV PORT=4003

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "4003"]
