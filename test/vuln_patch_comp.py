#coding=utf-8
'''
Created on 2016年1月4日
@author: Bert
'''

import time
from db import get_connection
from db.models import vulnerability_infos, softwares, cve_infos
from algorithm.ast import serializedAST, get_function_ast_root
from joern.all import JoernSteps
from multiprocessing import Pool
from openpyxl import Workbook

def vuln_patch_compare(conn, vuln_info, neo4jdb):
    cve_info = vuln_info.get_cve_info(conn)
    vuln_name = cve_info.cveid.replace("-", "_").upper() + "_VULN_" + vuln_info.vuln_func
    patch_name = cve_info.cveid.replace("-", "_").upper() + "_PATCHED_" + vuln_info.vuln_func
    
    start_time = time.time()
    status = ""
    vuln_func = get_function_ast_root(neo4jdb, vuln_name)
    if vuln_func is None:
        status = "vuln_func_not_found"
        return vuln_info, status, None, 0
    
    patched_func = get_function_ast_root(neo4jdb, patch_name)
    if patched_func is None:
        status = "patched_func_not_found"
        return vuln_info, status, None, 0
    
    s1 = serializedAST(neo4jdb, True, True)
    s2 = serializedAST(neo4jdb, False, True)
    s3 = serializedAST(neo4jdb, True, False)
    s4 = serializedAST(neo4jdb, False, False)
    
    r = {}
    if s1.genSerilizedAST(vuln_func) == s1.genSerilizedAST(patched_func):
        r['distinct_type_and_const'] = True
    if s2.genSerilizedAST(vuln_func) == s2.genSerilizedAST(patched_func):
        r['distinct_const_no_type'] = True
    if s3.genSerilizedAST(vuln_func) == s3.genSerilizedAST(patched_func):
        r['distinct_type_no_const'] = True
    if s4.genSerilizedAST(vuln_func) == s4.genSerilizedAST(patched_func):
        r['no_type_no_const'] = True
    
    end_time = time.time()
    cost = round(end_time - start_time, 2)
    return vuln_info, "success", r, cost
    
def process_line(conn, vuln_info, status, result, cost):
    ret = []
    ret.append(vuln_info.get_cve_info(conn).cveid)
    soft = vuln_info.get_cve_info(conn).get_soft(conn)
    ret.append(soft.software_name + "-" + soft.software_version)
    ret.append(vuln_info.vuln_func)
    ret.append(vuln_info.vuln_file)
    ret.append(status)
    if status == "success":
        ret.append(result["distinct_type_and_const"])
        ret.append(result["distinct_const_no_type"])
        ret.append(result["distinct_type_no_const"])
        ret.append(result["no_type_no_const"])
        ret.append(0)
    else:
        ret.append("-")
        ret.append("-")
        ret.append("-")
        ret.append("-")
        ret.append(0)
        
def vuln_patch_comp_proc():
    db_conn = get_connection()
    if db_conn is None:
        print u"数据库连接失败"
        return
    
    neo4jdb = JoernSteps()
    try:
        neo4jdb.setGraphDbURL('http://localhost:7474/db/data/')
        neo4jdb.connectToDatabase()
    except:
        print u"图形数据库连接失败"
        return
    
    cur = db_conn.cursor()
    cur.execute("select * from vulnerability_infos")
    infos = cur.fetchall()
    cur.close()
    
    rets = []
    pool = Pool(processes = 10)
    for info in infos:
        rets.append(pool.apply(vuln_patch_compare, (db_conn, vulnerability_infos(info), neo4jdb)))
    
    pool.close()
    pool.join()
    print "all done!"
    
    wb = Workbook()
    ws = wb.active()
    ws.title = u"测试结果"
    header = [u'CVE编号', u"软件版本", u"漏洞函数", u"漏洞文件",u"状态", "distinct_type_and_const" , "distinct_const_no_type",
              "distinct_type_no_const", "no_type_no_const", "cost"]
    ws.append(header)
    for r in rets:
        vuln_info, status, result, cost = r.get()
        ret = process_line(db_conn, vuln_info, status, result, cost)
        ws.append(ret)
    
    wb.save("result.xlsx")
    