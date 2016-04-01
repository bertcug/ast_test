#coding=utf-8
'''
Created on 2016年4月1日

@author: Bert
'''
import sys
sys.path.append("..")

from db.models import get_connection
from db.models import vulnerability_info, softwares, cve_infos
from openpyxl import Workbook
from segement_comp import get_type_mapping_table
from py2neo import Graph

def get_var_mapping():
    
    db_conn = get_connection()
    if db_conn is None:
        print u"数据库连接失败"
        return

    cur = db_conn.cursor()
    cur.execute("select * from vulnerability_info")
    rets = cur.fetchall()
    
    neo4j_db = Graph()
    wb = Workbook()
    ws = wb.active
    
    infos = []
    for ret in rets:
        soft = vulnerability_info(ret).get_cve_info(db_conn).get_soft(db_conn)
        if soft.software_name == "ffmpeg":
            infos.append(ret)
    
    for info in infos:
        vuln_info = vulnerability_info(info)
        cve_info = vuln_info.get_cve_info(db_conn)
        vuln_name = cve_info.cveid.replace("-", "_").upper() + "_VULN_" + vuln_info.vuln_func
        var_map = get_type_mapping_table(neo4j_db, vuln_name)
        ws.append((vuln_name, var_map.__str__()))
    wb.save("ffmpeg_var_map.xlsx")
    print "done!"

if __name__ == "__main__":
    get_var_mapping()
