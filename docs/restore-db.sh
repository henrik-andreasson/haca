#!/bin/bash


if [ "x${DB_RESTORE_ACTION}" == "xnone" ] ; then
  echo "DB_RESTORE_ACTION was set to skip db restore"
  echo "will exit"
  exit 0
fi

if [ "x${DB_RESTORE_ACTION}" == "xsmall" ] ; then
  echo "DB_RESTORE_ACTION was set to ${DB_RESTORE_ACTION} db restore"
  echo "todo"
fi

if [ "x${DB_RESTORE_ACTION}" == "xmedium" ] ; then
  echo "DB_RESTORE_ACTION was set to ${DB_RESTORE_ACTION} db restore"
  echo "todo"
fi

if [ "x${DB_RESTORE_ACTION}" == "xlarge" ] ; then
  echo "DB_RESTORE_ACTION was set to ${DB_RESTORE_ACTION} db restore"
  echo "todo"
fi

# default small backup file
MYSQL_BACKUP_FILE="${MYSQL_BACKUP_FILE:-certservice-2019-04-28_11.35.16.sql}"

if [ ! -f "${MYSQL_BACKUP_FILE}" ] ; then
  echo "File specifiled for restore does not exist: <${MYSQL_BACKUP_FILE}>"
  echo "Filelist: "
  ls
  exit -1

fi

/ansible/wait-for-it.sh --host=db --port=3306

ansible-playbook -i /ansible/hosts \
        --connection=local \
        -vv \
         /ansible/playbook-restore-db \
        --extra-vars  "mysql_backup_file=${MYSQL_BACKUP_FILE}"
