#coding=utf-8
'''
Created on 2016年1月4日
@author: Bert
'''

import time, datetime
from db.models import get_connection
from db.models import vulnerability_info, softwares, cve_infos
from algorithm.ast import serializedAST, get_function_ast_root
from openpyxl import Workbook
from py2neo import Graph
import re
from algorithm.suffixtree import suffixtree

def vuln_patch_compare(conn, neo4jdb, vuln_info, worksheet, suffix_tree_obj):
    
    cve_info = vuln_info.get_cve_info(conn)
    print "[%s] processing %s" % (datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"), cve_info.cveid)
    
    vuln_name = cve_info.cveid.replace("-", "_").upper() + "_VULN_" + vuln_info.vuln_func
    patch_name = cve_info.cveid.replace("-", "_").upper() + "_PATCHED_" + vuln_info.vuln_func
    
    start_time = time.time()
    status = ""
    vuln_func = get_function_ast_root(neo4jdb, vuln_name)
    if vuln_func is None:
        status = "vuln_func_not_found"
        
        line = process_line(conn, vuln_info, status, None, 0)
        worksheet.append(line)
        return
    
    patched_func = get_function_ast_root(neo4jdb, patch_name)
    if patched_func is None:
        status = "patched_func_not_found"
        
        line = process_line(conn, vuln_info, status, None, 0)
        worksheet.append(line)
        return
    
    pattern1 = serializedAST(neo4jdb, True, True).genSerilizedAST(vuln_func)
    pattern2 = serializedAST(neo4jdb, False, True).genSerilizedAST(vuln_func)  
    pattern3 = serializedAST(neo4jdb, True, False).genSerilizedAST(vuln_func)
    pattern4 = serializedAST(neo4jdb, False, False).genSerilizedAST(vuln_func)
    
    #delete FunctionDef and CompoundStatement node
    prefix_str = r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);"
    pattern1 = re.sub(prefix_str, "", pattern1)
    pattern2 = re.sub(prefix_str, "", pattern2)
    pattern3 = re.sub(prefix_str, "", pattern3)
    pattern4 = re.sub(prefix_str, "", pattern4)
    
    s1 = serializedAST(neo4jdb, True, True)
    s2 = serializedAST(neo4jdb, False, True)
    s3 = serializedAST(neo4jdb, True, False)
    s4 = serializedAST(neo4jdb, False, False)
    
    report = {}
    if suffix_tree_obj.search(s1.genSerilizedAST(vuln_func), pattern1):
            report['distinct_type_and_const'] = True
        
    if suffix_tree_obj.search(s2.genSerilizedAST(vuln_func), pattern2):
        report['distinct_const_no_type'] = True
        
    if suffix_tree_obj.search(s3.genSerilizedAST(vuln_func), pattern3):
        report['distinct_type_no_const'] = True
        
    if suffix_tree_obj.search(s4.genSerilizedAST(vuln_func), pattern4):
        report['no_type_no_const'] = True
       
    status = "success"
    end_time = time.time()
    cost = round(end_time - start_time, 2)
    
    line = process_line(conn, vuln_info, status, report, cost)
    worksheet.append(line)
     
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
    
    neo4jdb = Graph()
    suffix_tree_obj = suffixtree()
    
    cur = db_conn.cursor()
    cur.execute("select * from vulnerability_info where is_in_db=1")
    rets = cur.fetchall()
    
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
    
    for info in infos:
        vuln_patch_compare(db_conn, neo4jdb, vulnerability_info(info), ws, suffix_tree_obj)
    
    suffix_tree_obj.close()
    wb.save("result.xlsx")
    
    print "all works done!"

def patch_segement_comp(db1, vuln_func, db2, patch_segement, suffix_obj):
    
    start_time =  time.time()
    
    pattern1 = serializedAST(db2, True, True).genSerilizedAST(patch_segement)
    pattern2 = serializedAST(db2, False, True).genSerilizedAST(patch_segement)  
    pattern3 = serializedAST(db2, True, False).genSerilizedAST(patch_segement)
    pattern4 = serializedAST(db2, False, False).genSerilizedAST(patch_segement)
    
    #delete FunctionDef and CompoundStatement node
    prefix_str = r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);"
    pattern1 = re.sub(prefix_str, "", pattern1)
    pattern2 = re.sub(prefix_str, "", pattern2)
    pattern3 = re.sub(prefix_str, "", pattern3)
    pattern4 = re.sub(prefix_str, "", pattern4)
    
    s1 = serializedAST(db1, True, True)
    s2 = serializedAST(db1, False, True)
    s3 = serializedAST(db1, True, False)
    s4 = serializedAST(db1, False, False)
    
    report = {}
    if suffix_obj.search(s1.genSerilizedAST(vuln_func), pattern1):
            report['distinct_type_and_const'] = True
        
    if suffix_obj.search(s2.genSerilizedAST(vuln_func), pattern2):
        report['distinct_const_no_type'] = True
        
    if suffix_obj.search(s3.genSerilizedAST(vuln_func), pattern3):
        report['distinct_type_no_const'] = True
        
    if suffix_obj.search(s4.genSerilizedAST(vuln_func), pattern4):
        report['no_type_no_const'] = True
    
    end_time = time.time()
    cost = round(end_time - start_time, 2)
    
    return report, cost

def segement_compare_proc():
    pass
    
if __name__ == "__main__":
    vuln_patch_comp_proc()
    
