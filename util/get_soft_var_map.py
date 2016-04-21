# coding=utf-8
'''
Created on 2016年4月21日

@author: Bert
'''
import sys
sys.path.append("..")

from algorithm.ast import get_all_functions, get_function_ast_root, serializedAST, get_function_file
from segement_comp import get_type_mapping_table
from py2neo import Graph
import sqlite3

def get_software_var_map(soft, port):
    neo4j_db = Graph("http://127.0.0.1:%d/db/data/" % port)
    sql_db = sqlite3.connect("soft_var_map.db")
    sql_db.execute('''create table if not exists %s(
            func_id INT PRIMARY KEY,
            func_name CHAR(100) NOT NULL,
            file CHAR(200) NOT NULL,
            var_map TEXT NOT NULL)''' % soft_name)
    sql_db.commit()
    
    funcs = get_all_functions(neo4j_db)
    for func in funcs:
        # 查重
        ret = sql_db.execute("select * from %s where func_id=%d" % (soft, func._id))
        if ret.fetchone():
            continue
        
        ast_root = get_function_ast_root(neo4j_db, func)
        func_file = get_function_file(neo4j_db, func)
        ser = serializedAST()
        ser.genSerilizedAST(ast_root)
        var_map = ser.variable_maps
        
        
        sql_db.execute("insert into %s values(%d, %s, %s, %s)" %(soft, func._id,
                                                                 func.properties[u'name'],
                                                                 func_file, var_map.__str__()))
        sql_db.commit()
    
    print "all works done!"
        