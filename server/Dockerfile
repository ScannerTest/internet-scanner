FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8080

VOLUME ["/data"]
ENV SCANNER_DB=/data/scanner.db

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
