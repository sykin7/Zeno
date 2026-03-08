FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data
EXPOSE 8787
CMD ["gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:8787", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
