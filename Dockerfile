FROM python:3.10-alpine

WORKDIR /

COPY ./requirements.txt /requirements.txt

RUN pip install --upgrade pip setuptools wheel && \
    pip install --upgrade -r /requirements.txt

COPY ./app /app
COPY database.db /app/database.db

WORKDIR /app

RUN --mount=type=secret,id=PUBLIC_KEY_FILE \
    cat /run/secrets/PUBLIC_KEY_FILE > /app/publicKey.pem
RUN --mount=type=secret,id=PRIVATE_KEY_FILE \
    cat /run/secrets/PRIVATE_KEY_FILE > /app/privateKey.pem
RUN --mount=type=secret,id=VAULT_KEY_FILE \
    cat /run/secrets/VAULT_KEY_FILE > /app/vaultKey.txt

EXPOSE 80
CMD ["fastapi", "run", "main.py", "--port", "80"]
