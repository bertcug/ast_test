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
import argparse

def get_software_var_map(soft, port):
    neo4j_db = Graph("http://127.0.0.1:%d/db/data/" % port)
    sql_db = sqlite3.connect("soft_var_map.db")
    sql_db.execute('''create table if not exists %s(
            func_id INT PRIMARY KEY,
            func_name CHAR(100) NOT NULL,
            file CHAR(200) NOT NULL,
            var_map TEXT NOT NULL)''' % soft)
    sql_db.commit()
    
    funcs = get_all_functions(neo4j_db)
    for func in funcs:
        # 查重
        ret = sql_db.execute("select * from %s where func_id=%d" % (soft, func._id))
        if ret.fetchone():
            continue
        
        ast_root = get_function_ast_root(neo4j_db, func)
        func_file = get_function_file(neo4j_db, func)
        ser = serializedAST(neo4j_db)
        ser.genSerilizedAST(ast_root)
        var_map = ser.variable_maps
        
        query = "insert into %s values(%d, %s, %s, %s)" %(soft, func._id,
            func.properties[u'name'],func_file, var_map.__str__())
        try:
            sql_db.execute(query)
            sql_db.commit()
        except Exception,e:
            print "query sql is:", query
            print e
    
    print "all works done!"

if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    
    parse.add_argument("soft", help="software")
    parse.add_argument("port", type=int, help="neo4j port")
    args = parse.parse_args()
    
    get_software_var_map(args.soft, args.port)
        