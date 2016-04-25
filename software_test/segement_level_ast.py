#coding=utf-8

import sys
sys.path.append("..")
import time
import traceback
import datetime
import re
import sqlite3
from py2neo import Graph
from openpyxl import Workbook
from algorithm.ast import get_function_ast_root
from algorithm.ast import get_all_functions, get_function_node
from algorithm.ast import serializedAST
from algorithm.ast import get_function_file
from algorithm.suffixtree import suffixtree


def func_similarity_segement_level(db1, funcs, db2, func_name, db_table):
    # @db1 待比对数据库
    # @db2 代码段数据库
    # @func_name 代码段构成的函数名
    neo4j_db1 = Graph(db1)
    neo4j_db2 = Graph(db2)
    suffix_tree_obj = suffixtree()
   
    #sqlite
    db_conn = sqlite3.connect("/home/bert/Documents/data/soft_test.db")
    db_conn.execute("""create table if not exists %s(
        func_id INT PRIMARY KEY,
        func_name CHAR(100) NOT NULL,
        file CHAR(200) NOT NULL,
        vuln_segement CHAR(100) NOT NULL,
        distinct_type_and_const BOOLEAN,
        distinct_const_no_type BOOLEAN,
        distinct_type_no_const BOOLEAN,
        no_type_no_const BOOLEAN)""" % db_table)
    db_conn.commit()
    
    target_func = get_function_ast_root(neo4j_db2, func_name)
    if target_func is None:
        print "%s is not found" % func_name
        return
     
    pattern1 = serializedAST(neo4j_db2, True, True).genSerilizedAST(target_func)[0][:-1]
    pattern2 = serializedAST(neo4j_db2, False, True).genSerilizedAST(target_func)[0][:-1]  # 所有类型变量映射成相同值
    pattern3 = serializedAST(neo4j_db2, True, False).genSerilizedAST(target_func)[0][:-1]
    pattern4 = serializedAST(neo4j_db2, False, False).genSerilizedAST(target_func)[0][:-1]
    
    prefix_str = r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);"
    pattern1 = re.sub(prefix_str, "", pattern1)
    pattern2 = re.sub(prefix_str, "", pattern2)
    pattern3 = re.sub(prefix_str, "", pattern3)
    pattern4 = re.sub(prefix_str, "", pattern4)
    
    for func in funcs:
        print "[%s] processing %s VS %s" % (
                                   datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"),
                                   func(1), func_name)
        
        ast_root = get_function_ast_root(neo4j_db1, func(0))
        if ast_root is None:
            print "function not found:", func(0), func(1)
        
        s1 = serializedAST(neo4j_db1, True, True).genSerilizedAST(ast_root)[0][:-1]
        s2 = serializedAST(neo4j_db1, False, True).genSerilizedAST(ast_root)[0][:-1]
        s3 = serializedAST(neo4j_db1, True, False).genSerilizedAST(ast_root)[0][:-1]
        s4 = serializedAST(neo4j_db1, False, False).genSerilizedAST(ast_root)[0][:-1] 
        
        f = get_function_file(neo4j_db1, func)
        
        report = {}
        try:
            if suffix_tree_obj.search(s1, pattern1):
                report['distinct_type_and_const'] = True
            else:
                report['distinct_type_and_const'] = False
            
            if suffix_tree_obj.search(s2, pattern2):
                report['distinct_const_no_type'] = True
            else:
                report['distinct_const_no_type'] = False
            
            if suffix_tree_obj.search(s3, pattern3):
                report['distinct_type_no_const'] = True
            else:
                report['distinct_type_no_const'] = False
            
            if suffix_tree_obj.search(s4, pattern4):
                report['no_type_no_const'] = True
            else:
                report['no_type_no_const'] = False
                
            query = "insert into %s values(?,?,?,?,?,?,?,?,?)" % db_table
            db_conn.execute(query, (func(0), func(1), func(2), func_name, report['distinct_type_and_const'],
                              report['distinct_const_no_type'],
                              report['distinct_type_no_const'],
                              report['no_type_no_const'])
                            )
            db_conn.commit()
            
        except Exception,e:
            log_file = open("suffix_tree_error.log","a")
            log_file.writelines(
                                [datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S") + " " + e,
                                 s1, pattern1])
            log_file.flush()
            log_file.close()
                         
def ffmpeg_search_proc():
    db1 = "http://127.0.0.1:7475/db/data/" #假设软件数据库开启在7475端口
    db2 = "http://127.0.0.1:7473/db/data/" #假设代码段数据库开启在7476
    
    neo4j_db = Graph(db1)
    #假设只测试一个代码段函数
    segement_funcs = ["CVE_2013_0861_VULN_COMPLETE_0",]
    soft_db = sqlite3.connect("/home/bert/Documents/data/soft_var_map.db")
    ret = soft_db.execute("select * from ffmpeg")
    funcs = ret.fetchall()
    print "get all functions OK"
    
    for segement in segement_funcs:
        try:
            func_similarity_segement_level(db1, funcs, db2, segement, "ffmpeg")
        except Exception,e:
            print e
            traceback.print_exc()
        
    print "all works done!"

def wireshark_search_proc():
    db1 = "http://127.0.0.1:7476/db/data/" #假设软件数据库开启在7475端口
    db2 = "http://127.0.0.1:7473/db/data/"  #假设代码段数据库开启在7476
    
    #假设只测试一个代码段函数
    segement_funcs = ["CVE_2013_4933_VULN_COMPLETE_0",]
    soft_db = sqlite3.connect("/home/bert/Documents/data/soft_var_map.db")
    ret = soft_db.execute("select * from wireshark")
    funcs = ret.fetchall()
    print "get all functions OK"
    
    for segement in segement_funcs:
        try:
            func_similarity_segement_level(db1, funcs, db2, segement,"wireshark")
        except Exception,e:
            print e
            traceback.print_exc()
    
    print "all works done!"
    
if __name__ == "__main__":
    arg = sys.argv[1]
    if arg == "wireshark":
        wireshark_search_proc()
    elif arg == "ffmpeg":
        ffmpeg_search_proc()
    else:
        print "error"
        