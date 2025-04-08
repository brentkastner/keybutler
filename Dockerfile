# Use Python base image
FROM python:3.11

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    FLASK_DEBUG=${FLASK_DEBUG:-false} \
    FLASK_APP=app.py \
    FLASK_RUN_HOST=0.0.0.0 \
    SQLITE_DB=sqlite:///vaultdb.sqlite3 \
    JWT_SECRET_KEY=nevergonnagiveyouupnevergonnaletyoudown

# Set working directory
WORKDIR /app

# Copy application files
COPY app /app

# Install dependencies
#RUN apt-get install -y sqlite3
RUN pip install --no-cache-dir -r requirements.txt

# Expose Flask default port
EXPOSE 9080

# Start Flask server
#CMD ["flask", "run"]
CMD [ "gunicorn", "--bind", "0.0.0.0:9080", "--workers", "4", "app:app"]