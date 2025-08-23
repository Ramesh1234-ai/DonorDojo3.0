CREATE DATABASE IF NOT EXISTS blooddb;
CREATE USER 'dbuser'@'localhost' IDENTIFIED BY 'dbpass';
GRANT ALL PRIVILEGES ON blooddb.* TO 'dbuser'@'localhost';
FLUSH PRIVILEGES;

-- If MySQL 8 auth plugin causes issues:
ALTER USER 'dbuser'@'localhost' IDENTIFIED WITH mysql_native_password BY 'dbpass';
FLUSH PRIVILEGES;

# paste into a file or run with `python -c "..."` from project root
import sqlite3
conn = sqlite3.connect('database.db')
cur = conn.cursor()
for row in cur.execute('SELECT id,name,email,phone,subject,message,created_at FROM contact_message ORDER BY created_at DESC'):
    print(row)
conn.close()