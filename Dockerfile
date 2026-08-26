FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/hcvf

RUN addgroup --system hcvf && adduser --system --ingroup hcvf hcvf

COPY requirements.txt ./
RUN python -m pip install --upgrade pip && \
    python -m pip install -r requirements.txt

COPY --chown=hcvf:hcvf app ./app
COPY --chown=hcvf:hcvf worker ./worker
COPY --chown=hcvf:hcvf alembic ./alembic
COPY --chown=hcvf:hcvf alembic.ini ./alembic.ini

USER hcvf

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
