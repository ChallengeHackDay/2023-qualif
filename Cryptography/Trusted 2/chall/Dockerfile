FROM python:3.9-alpine
WORKDIR /app
RUN apk update && apk add socat
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY flag.txt .
COPY trusted2.py .
RUN chmod +x trusted2.py
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/app/trusted2.py"]