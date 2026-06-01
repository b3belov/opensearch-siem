FROM python:3.12-alpine
WORKDIR /app
COPY ingest-edge/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY ingest-edge/app.py /app/app.py
EXPOSE 5044
CMD ["python", "/app/app.py"]
