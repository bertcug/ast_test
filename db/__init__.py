import MySQLdb

def get_connection():
    try:
        conn = MySQLdb.connect(host="211.69.198.89", port=3306, user="bert", passwd="qazwsxedc", db="code_simialrity")
        return conn
    except:
        return None