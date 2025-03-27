FROM python:3.10-alpine

WORKDIR /

COPY ./requirements.txt /requirements.txt

RUN pip install --upgrade pip setuptools wheel && \
    pip install --upgrade -r /requirements.txt

COPY ./app /app
EXPOSE 80
CMD ["fastapi", "run", "app/main.py", "--port", "80"]
