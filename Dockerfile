FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY alembic.ini ./alembic.ini
COPY alembic/ ./alembic/
COPY app/ ./app/
COPY worker/ ./worker/

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
