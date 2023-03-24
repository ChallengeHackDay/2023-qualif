FROM python:3.9-alpine
WORKDIR /app
RUN apk update && apk add socat
COPY flag.txt .
COPY trusted.py .
RUN chmod +x trusted.py
EXPOSE 1338
CMD ["socat", "TCP-LISTEN:1338,reuseaddr,fork", "EXEC:/app/trusted.py"]