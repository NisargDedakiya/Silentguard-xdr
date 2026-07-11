FROM python:3.11-slim

WORKDIR /app

# psycopg2-binary lets the server talk to the Postgres service in compose.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt psycopg2-binary

COPY app ./app

EXPOSE 8000

# DATABASE_URL, SG_ADMIN_TOKEN, SG_ENROLL_TOKEN are supplied by compose/env.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
