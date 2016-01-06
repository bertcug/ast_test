#coding=utf-8
'''
Created on Jan 6, 2016

@author: bert
'''

from py2neo import Graph as datebase
from algorithm.graph import get_cfg_edges
from algorithm.ast import get_function_node
from igraph import Graph
'''
def get_properties(dict):
    properties = {}
    for (key, value) in dict.items():
        properties[str(key)]=value
    return properties
        
db = datebase()
g = Graph(directed = True)

func_node = get_function_node(db, "CVE_2013_0869_VULN_field_end")
edges = get_cfg_edges(db, func_node)
list = []
for edge in edges:
    g.add_vertex(name=str(edge.start_node._id))
    list.append(str(edge.start_node._id))

vs = g.vs()
for name in list:
    if vs.find(name=name):
        print True
    else:
        print False
'''

'''
db = datebase()
func_node = get_function_node(db, "CVE_2013_0869_VULN_field_end")
from algorithm.graph import translate_cfg
g = translate_cfg(db, func_node)
print g
'''

from algorithm.ast import get_function_node
from algorithm.graph import func_cfg_similarity
import time
import py2neo
from db.models import vulnerability_info, cve_infos, get_connection
from algorithm.ast import get_function_node
import datetime

def func_cfg_similarity_process(vuln_info):
    conn = get_connection()
    neo4jdb = py2neo.Graph()
     
    start_time = time.time()
    cve_info = vuln_info.get_cve_info(conn)
    soft = cve_info.get_soft(conn)
    conn.close()
    
    print "[%s] processing %s" % (datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"),
                                   cve_info.cveid)
    
    vuln_name = cve_info.cveid.replace(u"-", u"_").upper() + u"_VULN_" + vuln_info.vuln_func
    patch_name = cve_info.cveid.replace(u"-", u"_").upper() + u"_PATCHED_" + vuln_info.vuln_func
    
    vuln_func = get_function_node(neo4jdb, vuln_name)
    if vuln_func is None:
        print "vuln_func_not_found"
        return
         
    patch_func = get_function_node(neo4jdb, patch_name)
    if patch_func is None:
        print  "patch_func_not_found"
        return
    
    match, simi = func_cfg_similarity(vuln_func, neo4jdb, patch_func, neo4jdb)
   
    #u"success"
    end_time = time.time()
    cost = round(end_time - start_time, 2)
    print match, simi, cost

if __name__ == "__main__":
    db_conn = get_connection()
    if db_conn is None:
        print u"数据库连接失败"
        exit(0)
    
    cur = db_conn.cursor()
    cur.execute("select * from vulnerability_info")
    rets = cur.fetchall()
    cur.close()
    infos = []
    for ret in rets:
        cve_info = vulnerability_info(ret).get_cve_info(db_conn)
        soft = cve_info.get_soft(db_conn)
        if soft.software_name == "ffmpeg" and cve_info.cveid=="cve-2013-0874":
            infos.append(ret)
    
    for info in infos:
        func_cfg_similarity_process(vulnerability_info(info))   
    