#coding=utf-8
'''
Created on 2016年1月4日
@author: Bert
'''

import time, datetime
from db.models import get_connection
from db.models import vulnerability_info, softwares, cve_infos
from algorithm.ast import serializedAST, get_function_ast_root
from joern.all import JoernSteps
from multiprocessing import Pool
from openpyxl import Workbook
from openpyxl.reader.excel import load_workbook
import multiprocessing
from py2neo import Graph

def vuln_patch_compare(vuln_info, lock):
    conn = get_connection()
    neo4jdb = Graph()
    
    cve_info = vuln_info.get_cve_info(conn)
    print "[%s] processing %s" % (datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"), cve_info.cveid)
    
    vuln_name = cve_info.cveid.replace("-", "_").upper() + "_VULN_" + vuln_info.vuln_func
    patch_name = cve_info.cveid.replace("-", "_").upper() + "_PATCHED_" + vuln_info.vuln_func
    
    start_time = time.time()
    status = ""
    vuln_func = get_function_ast_root(neo4jdb, vuln_name)
    if vuln_func is None:
        status = "vuln_func_not_found"
        
        lock.acquire()
        wb=load_workbook("result.xlsx")
        ws=wb.active()
        line = process_line(conn, vuln_info, status, None, 0)
        ws.append(line)
        wb.save("result.xlsx")
        lock.release()
    
        return
    
    patched_func = get_function_ast_root(neo4jdb, patch_name)
    if patched_func is None:
        status = "patched_func_not_found"
        
        lock.acquire()
        wb=load_workbook("result.xlsx")
        ws=wb.active()
        line = process_line(conn, vuln_info, status, None, 0)
        ws.append(line)
        wb.save("result.xlsx")
        lock.release()
        
        return
    
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
    
    status = "success"
    end_time = time.time()
    cost = round(end_time - start_time, 2)
    
    lock.acquire()
    wb=load_workbook("result.xlsx")
    ws=wb.active
    line = process_line(conn, vuln_info, status, r, cost)
    ws.append(line)
    wb.save("result.xlsx")
    lock.release()
        
    return
    
def process_line(conn, vuln_info, status, result, cost):
    ret = []
    ret.append(vuln_info.get_cve_info(conn).cveid)
    soft = vuln_info.get_cve_info(conn).get_soft(conn)
    ret.append(soft.software_name + "-" + soft.software_version)
    ret.append(vuln_info.vuln_func)
    ret.append(vuln_info.vuln_file[41:])
    ret.append(status)
    if status == "success":
        ret.append(result["distinct_type_and_const"])
        ret.append(result["distinct_const_no_type"])
        ret.append(result["distinct_type_no_const"])
        ret.append(result["no_type_no_const"])
        ret.append(cost)
    else:
        ret.append("-")
        ret.append("-")
        ret.append("-")
        ret.append("-")
        ret.append(cost)
    
    return ret
        
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
    cur.execute("select * from vulnerability_info")
    rets = cur.fetchall()
    cur.close()
    infos = []
    for ret in rets:
        soft = vulnerability_info(ret).get_cve_info(db_conn).get_soft(db_conn)
        if soft.software_name == "ffmpeg":
            infos.append(ret)
        
    
    wb = Workbook()
    ws = wb.active
    ws.title = u"测试结果"
    header = [u'CVE编号', u"软件版本", u"漏洞函数", u"漏洞文件",u"状态", "distinct_type_and_const" , "distinct_const_no_type",
              "distinct_type_no_const", "no_type_no_const", "cost"]
    ws.append(header)
    wb.save("result.xlsx")
    
    pool = Pool(processes = 10)
    lock = multiprocessing.Manager().Lock()
    for info in infos:
        pool.apply(vuln_patch_compare, (vulnerability_info(info),lock))
    
    pool.close()
    pool.join()
    
    print "all works done!"
    
if __name__ == "__main__":
    vuln_patch_comp_proc()
    
