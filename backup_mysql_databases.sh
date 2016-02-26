#!/bin/bash
# Maintainer: Vitaly Khabarov <vitkhab@gmail.com>
# Description: This script creates user for backup and backups selected databases
# Usage: ./backup_mysql_databases.sh -d database[,database...]

DBUSER="dump"
SECRET='/etc/mysql_backup.secret'
DUMPDIR="/srv/mysql-backup/"
DATE=`date +%y%m%d`

while [[ $# > 0 ]]
do
key="$1"

case $key in
   # Parse DBs list from 'db1,db2,db3...' to 'db1 db2 db3 ...'
   -d|--databases)
    DBS="${2//,/ }"
    shift # past argument
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

function check_priv {
    mysql -u $DBUSER -p$DBPASS -e 'SHOW TABLES' $1 > /dev/null 2>&1
}

function grant_priv {
    # Read authentication data
    if [ -z $MYSQLUSER ]
    then
        read -p "Input MySQL admin user (default root): " MYSQLUSER
        if [ -z $MYSQLUSER ]
        then
            MYSQLUSER='root'
        fi
    fi

    while [ -z $MYSQLPASS ]
    do
        read -s -p "Input MySQL password: " MYSQLPASS
        echo
    done

    mysql -u $MYSQLUSER -p$MYSQLPASS -e "GRANT SHOW VIEW, LOCK TABLES, SELECT ON $1.* TO '"$DBUSER"'@'localhost' IDENTIFIED BY '"$DBPASS"'"
}

function backup {
    for DB in $DBS
    do
        check_priv $DB
        if [ $? -ne 0 ]
        then
            grant_priv $DB
        fi

        mysqldump -u $DBUSER -p$DBPASS $DB | gzip -9 > $DUMPDIR$DB.sql.gz
    done
}

function init {
    password1="a"
    password2="b"
    while [ "$password1" != "$password2" ]
    do
        read -p 'Enter new password for dump user: ' -s password1
        read -p $'\nReenter password: ' -s password2
        if [ "$password1" == "$password2" ]
        then
                password="$password1"
        else
                echo $'\nPasswords dismatched.'
        fi
    done

    echo $password > $SECRET
    chmod 0700 $SECRET
}

if [ ! -e $SECRET ]
then
    init
fi

DBPASS=`cat $SECRET`

backup
