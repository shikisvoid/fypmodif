FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY train.py .

# Models directory (will be mounted as volume or copied)
RUN mkdir -p /app/models /app/data

EXPOSE 5000

ENV ML_PORT=5000

CMD ["python", "app.py"]

