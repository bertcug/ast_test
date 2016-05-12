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
import traceback
import datetime

def get_software_var_map(soft, port):
    neo4j_db = Graph("http://127.0.0.1:%d/db/data/" % port)
    sql_db = sqlite3.connect("/home/bert/Documents/data/" + soft + ".db")
    sql_db.execute('''create table if not exists %s(
            func_id INT PRIMARY KEY,
            func_name CHAR(100) NOT NULL,
            file CHAR(200) NOT NULL,
            var_map TEXT NOT NULL,
            ast_type_const TEXT NOT NULL,
            ast_type_only TEXT NOT NULL,
            ast_const_only TEXT NOT NULL,
            ast_no_type_const TEXT NOT NULL,
            no_mapping TEXT NOT NULL)''' % soft)
    sql_db.commit()
    
    funcs = get_all_functions(neo4j_db)
    open(""+len(funcs).__str__(), "w")
    print "get all functions OK:", len(funcs)
    
    for func in funcs:
        # 查重
        ret = sql_db.execute("select * from %s where func_id=?" % soft, (func._id,))
        if ret.fetchone():
            continue
        
        print "[%s] processing %s " % ( datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"), func.properties[u'name'] )
        
        try:
            ast_root = get_function_ast_root(neo4j_db, func)
            func_file = get_function_file(neo4j_db, func)
            ser = serializedAST(neo4j_db)
            ret = ser.genSerilizedAST(ast_root)
            var_map = ser.variable_maps
            ast1 = ";".join(ret[0])
            ast2 = ";".join(ret[1])
            ast3 = ";".join(ret[2])
            ast4 = ";".join(ret[3])
            ast5 = ";".join(ret[4])       
        except Exception, e:
            traceback.print_exc()
            
        try:
            sql_db.execute('insert into %s values(?, ?, ?, ?, ?, ?, ?, ?,?)' % soft,
                           (func._id, func.properties[u'name'],func_file, var_map.__str__(), ast1, ast2, ast3, ast4, ast5))
            sql_db.commit()
        except Exception,e:
            print e
    
    print "all works done!"

if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    
    parse.add_argument("soft", help="software")
    parse.add_argument("port", type=int, help="neo4j port")
    args = parse.parse_args()
    
    get_software_var_map(args.soft, args.port)
        