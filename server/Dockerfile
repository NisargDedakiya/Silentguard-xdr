FROM python:3.11-slim

WORKDIR /app

# psycopg2-binary lets the server talk to the Postgres service in compose.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt psycopg2-binary

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
COPY docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh

EXPOSE 8000

# DATABASE_URL, SG_ADMIN_TOKEN, SG_ENROLL_TOKEN are supplied by compose/env.
# The entrypoint runs `alembic upgrade head` before launching uvicorn.
CMD ["./docker-entrypoint.sh"]
