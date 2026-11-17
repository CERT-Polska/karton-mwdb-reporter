FROM python:3.14-slim-trixie

WORKDIR /app/service
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt setuptools
COPY README.md ./README.md
COPY karton ./karton
COPY setup.py ./setup.py
RUN pip install .
ENTRYPOINT ["karton-mwdb-reporter"]
