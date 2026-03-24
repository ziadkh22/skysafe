import MySQLdb

# Try different common local root passwords
passwords = ['', 'root', 'mysql', 'admin', 'password', 'skysafe123database']

for pwd in passwords:
    try:
        conn = MySQLdb.connect(
            host='localhost',
            port=3306,
            user='root',
            password=pwd,
        )
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES;")
        dbs = [r[0] for r in cursor.fetchall()]
        print(f"SUCCESS with password='{pwd}'! Databases:", dbs)
        conn.close()
        break
    except Exception as e:
        print(f"Failed with password='{pwd}': {e}")
