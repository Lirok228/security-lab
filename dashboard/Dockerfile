FROM python:3.12-slim
WORKDIR /app
COPY app.py .
RUN pip install --no-cache-dir markdown
# reports и skills монтируются как volumes
CMD ["python3", "app.py"]
