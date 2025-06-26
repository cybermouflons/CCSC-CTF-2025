#!/bin/bash
SQL_SCRIPT="INSERT INTO Programs (Name, Description, File, Date_upload) VALUES ('Test', 'Desc', 'flag.st', strftime('%s', 'now'));"
sqlite3 /root/OpenPLC_v3/webserver/openplc.db "$SQL_SCRIPT"

SQL_AUTOST="UPDATE Settings SET Value = 'true' WHERE Key = 'Start_run_mode';"
sqlite3 /root/OpenPLC_v3/webserver/openplc.db "$SQL_AUTOST"

/root/OpenPLC_v3/start_openplc.sh