#/bin/sh

USER=root vncserver
service apache2 start
service mysql start
tail -f /var/log/apache2/access.log
