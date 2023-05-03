import sqlite3

PATH = "db//ald_anomalies.db"
fields = "src_ip, src_mac, dst_ip, dst_mac, timestamp, rule_rate, bad_rate"


def create_ald_anomaly_table():
    connect = sqlite3.connect(database=PATH)
    cur = connect.cursor()
    create_query = """
        CREATE TABLE IF NOT EXISTS ald_anomalies(
            src_ip TEXT,
            src_mac TEXT,
            dst_ip TEXT,
            dst_mac TEXT, 
            timestamp INTEGER,
            rule_rate REAL,
            bad_rate REAL
            );
        """
    connect.execute(create_query)
    connect.commit()
    cur.close()


def add_anomaly_object(parametrs: list):
    connect = sqlite3.connect(database=PATH)
    cur = connect.cursor()
    add_query = "INSERT INTO ald_anomalies (" + fields + ") VALUES " + str(parametrs) + ";"
    cur.execute(add_query)
    connect.commit()
    connect.close()

