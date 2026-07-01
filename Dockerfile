# A reproducible environment for pwmanager — mainly useful for the password
# generator and for CI, and for using the vault against a mounted volume.
#
#   docker build -t pwmanager .
#   docker run --rm -it -v "$PWD/data:/data" pwmanager --vault /data/vault.db --backend sqlite
#   docker run --rm pwmanager gen --length 32          # no vault needed
FROM python:3.12-slim

# Non-root user — a password tool should never run as root.
RUN useradd --create-home --uid 10001 vault
WORKDIR /app

COPY pyproject.toml README.md ./
COPY pwmanager.py ./
RUN pip install --no-cache-dir ".[argon2,clipboard]"

USER vault
ENTRYPOINT ["pwmanager"]
CMD ["--help"]
