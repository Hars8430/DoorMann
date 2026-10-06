# --- stage 1: build the React dashboard ---
FROM node:20-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# --- stage 2: python runtime, serving API + built dashboard on one port ---
FROM python:3.12-slim
WORKDIR /app

# corpus/generate_corpus.py picks a Unicode TTF that provably round-trips
# zero-width spaces (it probes candidates at startup). Slim images ship no
# fonts at all, so install DejaVu explicitly — otherwise the corpus step
# fails with "No usable Unicode TTF found".
RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY corpus/generate_corpus.py corpus/generate_corpus.py
COPY eval/ eval/
COPY --from=frontend-build /app/frontend/dist frontend/dist

RUN python corpus/generate_corpus.py && python eval/run_eval.py

EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
