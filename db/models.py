#coding=utf-8
'''
Created on 2016年1月4日

@author: Bert
'''
import MySQLdb

def get_connection():
    try:
        conn = MySQLdb.connect(host="211.69.198.89", port=3306,
                                user="bert", passwd="qazwsxedc",
                                 db="code_similarity")
        return conn
    except:
        return None

class cve_infos():
    info_id = 0
    cveid = ""
    diff_file = ""
    vuln_soft_id = 0
    cweid = ""
    user_id = 0
    
    def __init__(self, log):
        self.info_id = log[0]
        self.cveid = log[1]
        self.diff_file = log[2]
        self.user_id = log[3]
        self.vuln_soft_id = log[4]
        self.cweid = log[5]
    
    def get_soft(self, conn):
        cur = conn.cursor()
        cur.execute("select * from  softwares where software_id=%d" % self.vuln_soft_id)
        ret = cur.fetchone()
        cur.close()
        return softwares(ret)
    
def get_cve_info(conn, info_id):
    cur = conn.cursor()
    cur.execute("select * from cve_infos where indo_id=%d" % info_id)
    try:
        ret = cur.fetchone()
        cur.close()
        return cve_infos(ret)
    except:
        raise None
    
class softwares():
    software_id = 0
    software_name = ""
    software_version = ""
    sourcecodepath = ""
    neo4j_db = ""
    user_id = 0
    
    def __init__(self, log):
        self.software_id = log[0]
        self.software_name = log[1]
        self.software_version = log[2]
        self.sourcecodepath = log[3]
        self.neo4j_db = log[4]
        self.user_id = log[5]

def get_software(conn, soft_id):
    cur = conn.cursor()
    cur.execute("select * from softwares where software_id=%d" % soft_id)
    try:
        ret = cur.fetchone()
        cur.close()
        return softwares(ret)
    except:
        return None
    
class vulnerability_info():
    vuln_id = 0
    vuln_func = ""
    vuln_file = ""
    vuln_func_source = ""
    patched_func_source = ""
    cve_info_id = 0
    user_id = 0
    is_in_db = False
    vuln_type=""
    
    def __init__(self, log):
        self.vuln_id = log[0]
        self.vuln_func = log[1]
        self.vuln_file = log[2]
        self.vuln_func_source = log[3]
        self.patched_func_source = log[4]
        self.cve_info_id = log[5]
        self.user_id = log[6]
        self.is_in_db = log[7]
        self.vuln_type = log[8]
    
    def get_cve_info(self, conn):
        cur = conn.cursor()
        cur.execute("select * from cve_infos where info_id=%d" % self.cve_info_id)
        ret = cur.fetchone()
        cur.close()
        return cve_infos(ret)

def get_vuln_info(conn, info_id):
    cur = conn.cursor()
    cur.execute("select * from vulnerability_info where vuln_id=%d" % info_id)
    try:
        ret = cur.fetchone()
        cur.close()
        return vulnerability_info(ret)
    except:
        return None