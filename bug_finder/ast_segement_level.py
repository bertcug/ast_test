#coding=utf-8

import sys
sys.path.append("..")

import time
import datetime
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

def func_similarity_segement_level(db1, funcs, db2, func_name, suffix_tree_obj, worksheet):
    # @db1 待比对数据库
    # @db2 代码段数据库
    # @func_name 代码段构成的函数名
    
    start_time = time.time()
    
    target_func = get_function_ast_root(db2, func_name)
     
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
    for func in funcs:
        print "[%s] processing %s VS %s" % (
                                   datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"),
                                   func_name,func.properties[u'name'] )
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
            end_time = time.time()
            cost = end_time - start_time
            
            file = get_function_file(db1, func.properties[u'name'])[41:]
            worksheet.append(
                             (func_name, file, func.properties[u'name'],report['distinct_type_and_const'],
                              report['distinct_const_no_type'], report['distinct_type_no_const'],
                              report['distinct_type_no_const'], cost))
def ffmpeg_search_proc():
    db1 = Graph("http://127.0.0.1:7475/db/data/")  #假设软件数据库开启在7475端口
    db2 = Graph("http://127.0.0.1:7473/db/data/")  #假设代码段数据库开启在7476
    suffix_tree_obj = suffixtree()
    
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = u"ffmpeg代码段查找测试结果"
    header = [u'代码段', u"漏洞文件", u"漏洞函数", "distinct_type_and_const" , "distinct_const_no_type",
              "distinct_type_no_const", "no_type_no_const", u"耗时"]
    worksheet.append(header)
    workbook.save("ffmpeg_search.xlsx")
    
    #假设只测试一个代码段函数
    segement_funcs = ["CVE-2013-0861_VULN_COMPLETE_0",]
    funcs = get_all_functions(db1)
    
    for func_name in segement_funcs:
        try:
            func_similarity_segement_level(db1, funcs, db2, func_name, suffix_tree_obj, worksheet)
            workbook.save("ffmpeg_search.xlsx")
        except:
            print "error occured!"
    
    print "all works done!"

def wireshark_search_proc():
    db1 = Graph("http://localhost:7476/db/data/")  #假设软件数据库开启在7475端口
    db2 = Graph("http://localhost:7473/db/data/")  #假设代码段数据库开启在7476
    suffix_tree_obj = suffixtree()
    
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = u"wireshark代码段查找测试结果"
    header = [u'代码段', u"漏洞文件", u"漏洞函数", "distinct_type_and_const" , "distinct_const_no_type",
              "distinct_type_no_const", "no_type_no_const", u"耗时"]
    worksheet.append(header)
    workbook.save("wireshark_search.xlsx")
    
    #假设只测试一个代码段函数
    segement_funcs = ["CVE-2013-4933_VULN_COMPLETE_0",]
    funcs = get_all_functions(db1)
    
    for func_name in segement_funcs:
        try:
            func_similarity_segement_level(db1, funcs, db2, func_name, suffix_tree_obj, worksheet)
            workbook.save("wireshark_search.xlsx")
        except:
            print "error occured!"
    
    print "all works done!"
    
if __name__ == "__main__":
    arg = sys.argv[1]
    if arg == "wireshark":
        wireshark_search_proc()
    elif arg == "ffmpeg":
        ffmpeg_search_proc()
    else:
        print "error"