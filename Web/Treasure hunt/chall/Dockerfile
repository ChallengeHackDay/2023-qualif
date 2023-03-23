FROM manishfoodtechs/xfcefulldesktop_ubuntu20.4
RUN apt update -y
RUN apt install apache2 php php-mysql mysql-server -y
RUN apt install tightvncserver ; mkdir /root/.vnc
ADD passwd /root/.vnc/passwd
ADD init.sh /
RUN chmod +x /init.sh
RUN usermod -d /var/lib/mysql/ mysql
ADD dbConnection.sql /tmp/dbConnection.sql
RUN service mysql start ; mysql -u root --password="" -e "CREATE USER 'admin'@'localhost' IDENTIFIED BY 'Oi42oTR9SGDFGH';"; mysql -u root --password="" -e "GRANT ALL PRIVILEGES ON * . * TO 'admin'@'localhost';" ; mysql -u root --password="" -e "FLUSH PRIVILEGES" ;  mysql -u root --password="" -e "create database employees" ; mysql -u root --password="" employees < /tmp/dbConnection.sql
RUN rm /var/www/html/index.html
ADD ./app /var/www/html
ADD backgroundFlag.jpg /usr/share/backgrounds/xfce/background.jpg
ADD xfce4-desktop.xml /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml
ADD vncserver /usr/bin/vncserver
RUN chmod +x /usr/bin/vncserver
RUN rm -r /root/Win* /root/core /root/thinclient_drives /root/Desktop/*
CMD /init.sh

EXPOSE 80
EXPOSE 5901
