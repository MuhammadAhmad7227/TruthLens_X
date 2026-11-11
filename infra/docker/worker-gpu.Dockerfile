FROM nvidia/cuda:12.8.0-runtime-ubuntu22.04
WORKDIR /app
COPY backend/ /app/
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir -e .
USER 10001
CMD ["python3","-m","app.main"]
