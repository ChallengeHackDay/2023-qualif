FROM ubuntu:20.04

RUN apt update -y
RUN DEBIAN_FRONTEND=noninteractive apt install apache2 php php-xml -y
ADD ./app /var/www/html/
ADD flag.txt /
CMD service apache2 start ; tail -f /var/log/apache2/access.log
EXPOSE 80
