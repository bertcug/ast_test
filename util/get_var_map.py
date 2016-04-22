# coding=utf-8
'''
Created on 2016年4月1日

@author: Bert
'''
import sys
sys.path.append("..")

from db.models import get_connection
from db.models import vulnerability_info, softwares, cve_infos
from segement_comp import get_type_mapping_table
from py2neo import Graph
import sqlite3
import argparse

def get_var_mapping(soft_name):
    
    db_conn = get_connection()
    if db_conn is None:
        print u"数据库连接失败"
        return

    cur = db_conn.cursor()
    cur.execute("select * from vulnerability_info")
    rets = cur.fetchall()
    
    neo4j_db = Graph()
    
    infos = []
    for ret in rets:
        soft = vulnerability_info(ret).get_cve_info(db_conn).get_soft(db_conn)
        if soft.software_name == soft_name:
            infos.append(ret)
    
    var_map_db = sqlite3.connect("var_map.db")
    var_map_db.execute('''create table if not exists %s(
            func_name CHAR(100) PRIMARY KEY,
            var_map TEXT NOT NULL)''' % soft_name)
    var_map_db.commit()
    
    print "There are %d functions" % len(infos)
    for info in infos:
        
        vuln_info = vulnerability_info(info)
        cve_info = vuln_info.get_cve_info(db_conn)
        if vuln_info.vuln_func == "None":
            continue
        
        vuln_name = cve_info.cveid.replace("-", "_").upper() + "_VULN_" + vuln_info.vuln_func
        patch_name = cve_info.cveid.replace("-", "_").upper() + "_PATCHED_" + vuln_info.vuln_func
        
        #check if exist
        ret = var_map_db.execute("select * from %s where func_name='%s'" % (soft_name, vuln_name))
        if not ret.fetchone():
            #VULN
            var_map = get_type_mapping_table(neo4j_db, vuln_name)
            var_map_db.execute('insert into %s values("%s", "%s")' % 
                               (soft_name, vuln_name, var_map.__str__()))
            var_map_db.commit()
        
        ret = var_map_db.execute("select * from %s where func_name='%s'" % (soft_name, patch_name))
        if not ret.fetchone():
            #PATCH
            var_map = get_type_mapping_table(neo4j_db, patch_name)
            var_map_db.execute('insert into %s values("%s", "%s")' % 
                               (soft_name, patch_name, var_map.__str__()))
            var_map_db.commit()
        
        
        
    print "done!"

if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    parse.add_argument("-soft","--software", help="software mame")
    parse.add_argument("-all", action="store_true", default=False, help="create all softwares, now linux, wireshark, ffmpeg")
    args = parse.parse_args()
    
    if args.all:
        get_var_mapping("linux")
        get_var_mapping("ffmpeg")
        get_var_mapping("wireshark")
    elif args.software:
        get_var_mapping(args.software)
    else:
        parse.print_help() 
            
