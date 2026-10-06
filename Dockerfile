# AI 蜜罐 — 全栈容器 (零第三方依赖, 无需 pip install)
FROM python:3.13-slim

WORKDIR /app
COPY . .

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

# 蜜罐默认端口: HTTP 8080 / 假 PG 5432 / Redis 6379 / SSH 2222 / 云元数据 80(可选)
# 控制台 (hive): 8899
EXPOSE 8080 5432 6379 8899

CMD ["python", "main.py", "--server", "--port", "8080"]
