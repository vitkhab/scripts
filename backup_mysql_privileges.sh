#!/bin/bash
# Maintainer: Vitaly Khabarov <vitkhab@gmail.com>
# Description: This script backups all MySQL users privileges with passwords to file
# Usage: ./backup_mysql_privileges.sh

BACKUPDEST=/srv/mysql-backup/grants.sql

# Clean up backup file
: > $BACKUPDEST

# Read authentication data
read -p "Input MySQL admin user (default root): " MYSQLUSER
if [ -z $MYSQLUSER ]
then
  MYSQLUSER='root'
fi

while [ -z $MYSQLPASS ]
do
  read -s -p "Input MySQL password: " MYSQLPASS
  echo 
done

# Get all MySQL users excluding system ones
users=`mysql -u $MYSQLUSER -p$MYSQLPASS -N -B -e "SELECT User,Host FROM mysql.user WHERE User != 'root' AND User != 'debian-sys-maint'" | awk '{print "\"" $1 "\"@\"" $2 "\""}'`

# Get MySQL users' privileges and write them to file
for i in $users
do
  mysql -u $MYSQLUSER -p$MYSQLPASS -N -B -e "SHOW GRANTS FOR $i" | sed 's/$/;/' >> $BACKUPDEST
done

chown root:root $BACKUPDEST
chmod 0700 $BACKUPDEST
