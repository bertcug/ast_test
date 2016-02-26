#coding=utf-8

from openpyxl import load_workbook, Workbook
from algorithm.ast import get_function_node
import time
import py2neo
import datetime

def segement_ast_similarity_process(vuln_name, patch_name, neo4jdb, worksheet):
    start_time = time.time()
    print "[%s] processing %s" % (datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"),
                                   vuln_name + " vs " + patch_name)
    
    #检查数据库里面是否可以找到该函数
    vuln_func = get_function_node(neo4jdb, vuln_name)
    if vuln_func is None:
        line = (vuln_name, patch_name, "vuln_func_not_found", "-", "-", "-", "-", 0)
        worksheet.append(line)
        return
    
    #检查数据库里面是否可以找到该函数    
    patch_func = get_function_node(neo4jdb, patch_name)
    if patch_func is None:
        line = (vuln_name, patch_name, "patch_func_not_found", "-", "-", "-", "-", 0)
        worksheet.append(line)
        return
    
    