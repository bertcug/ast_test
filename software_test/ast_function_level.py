#coding=utf-8
import sys
sys.path.append("..")

import time
import re
from py2neo import Graph
from openpyxl import Workbook

from algorithm.ast import get_function_ast_root
from algorithm.ast import get_function_return_type
from algorithm.ast import get_function_param_list
from algorithm.ast import filter_functions
from algorithm.ast import get_all_functions
from algorithm.ast import serializedAST
from algorithm.ast import get_function_file
from algorithm.suffixtree import suffixtree
from db.models import get_connection
from db.models import vulnerability_info

def func_similarity_astLevel(db1, funcs, db2, func_name, suffix_tree_obj, worksheet):
    # @db1 待比对数据库
    # @db2 漏洞特征数据库
    # @func_name 目标函数名
    
    target_func = get_function_ast_root(db2, func_name)
    return_type = get_function_return_type(db2, target_func)  # 获取目标函数返回值类型
    param_list = get_function_param_list(db2, target_func)  # 获取目标函数参数类型列表
    
    # funcs = getAllFuncs(db1) #获取所有函数
    filter_funcs = filter_functions(db1, funcs, return_type, param_list) # 过滤待比较函数
    
    pattern1 = serializedAST(db2, True, True).genSerilizedAST(target_func)[0][:-1]
    pattern2 = serializedAST(db2, False, True).genSerilizedAST(target_func)[0][:-1]  # 所有类型变量映射成相同值
    pattern3 = serializedAST(db2, True, False).genSerilizedAST(target_func)[0][:-1]
    pattern4 = serializedAST(db2, False, False).genSerilizedAST(target_func)[0][:-1]
    
    prefix_str = r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);"
    pattern1 = re.sub(prefix_str, "", pattern1)
    pattern2 = re.sub(prefix_str, "", pattern2)
    pattern3 = re.sub(prefix_str, "", pattern3)
    pattern4 = re.sub(prefix_str, "", pattern4)
    
    
    report_dict = {}
    for func in filter_funcs:
        ast_root = get_function_ast_root(db1, func.properties[u'name'])
        s1 = serializedAST(db1, True, True).genSerilizedAST(ast_root)[0][:-1]
        s2 = serializedAST(db1, False, True).genSerilizedAST(ast_root)[0][:-1]
        s3 = serializedAST(db1, True, False).genSerilizedAST(ast_root)[0][:-1]
        s4 = serializedAST(db1, False, False).genSerilizedAST(ast_root)[0][:-1] 
        
        report = {}
        if suffix_tree_obj.search(s1, pattern1):
            report['distinct_type_and_const'] = True
        
        if suffix_tree_obj.search(s2, pattern2):
            report['distinct_const_no_type'] = True
        
        if suffix_tree_obj.search(s3, pattern3):
            report['distinct_type_no_const'] = True
        
        if suffix_tree_obj.search(s4, pattern4):
            report['distinct_type_no_const'] = True
        
        if report['distinct_type_and_const'] or  report['distinct_const_no_type']\
            or report['distinct_type_no_const'] or report['no_type_no_const']:
            
            file = get_function_file(db1, func.properties[u'name'])[41:]
            worksheet.append(
                             (func_name, file, func.properties[u'name'],report['distinct_type_and_const'],
                              report['distinct_const_no_type'], report['distinct_type_no_const'],
                              report['distinct_type_no_const'] ))
                             
def astlevel_comp_proc():
    db_conn = get_connection()
    if db_conn is None:
        print u"数据库连接失败"
        return
    
    #选择所有ffmpeg的漏洞函数   
    cur = db_conn.cursor()
    cur.execute("select * from vulnerability_info")
    rets = cur.fetchall()
    
    func_names = []
    for ret in rets:
        vuln_info = vulnerability_info(ret)
        cve_info = vuln_info.get_cve_info(db_conn)
        soft = cve_info.get_soft(db_conn)
        
        if soft.software_name == "ffmpeg":
            func_names.append(cve_info.cveid.upper().replace("-", "_") + "_VULN_" + vuln_info.vuln_func )
    
    #特征数据库，默认开启在7474端口
    db2 = Graph() #默认连接7474端口
    db1 = Graph("http://localhost:7475/db/data") #假设7475端口是某ffmpeg的图形数据库
    suffix_tree_obj = suffixtree()
    
    wb = Workbook()
    ws = wb.active
    ws.title = u"AST函数级漏洞查找测试结果"
    header = [u'漏洞函数名', u"漏洞文件", u"漏洞函数", "distinct_type_and_const" , "distinct_const_no_type",
              "distinct_type_no_const", "no_type_no_const", "耗时"]
    ws.append(header)
    wb.save("ast_func.xlsx")
    
    all_funcs = get_all_functions(db2)
    for name in func_names:
        try:
            func_similarity_astLevel(db1, all_funcs, db2, name, suffix_tree_obj, ws)
            wb.save("ast_func.xlsx")
        except:
            print "error occured"
    
    suffix_tree_obj.close()
    
    print "all works done!"