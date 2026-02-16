FROM python:3.12-slim

RUN groupadd -r -g 1000 sysadmin && useradd -r -u 1000 -g sysadmin -m -d /app sysadmin

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sysadmin_ai.py soul.md __main__.py ./

# No kubectl, no docker, no curl — minimal attack surface
# Standard system tools (ps, ls, df, etc.) available from base image

USER sysadmin
ENV HOME=/app

EXPOSE 8080

ENTRYPOINT ["python", "-m", "sysadmin_ai"]
