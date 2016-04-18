# -*- coding:utf-8 -*-
import sys
sys.path.append("..")

from algorithm.ast import serializedAST, get_function_ast_root
from py2neo import Graph
import argparse

if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    parse.add_argument("-f", "--func", help="function name")
    parse.add_argument("-p", "--port", help="db port")
    args = parse.parse_args()
    
    func = args.func
    db = Graph("http://127.0.0.1:%d/db/data/" % args.port)
    
    ast_root = get_function_ast_root(db, func)
    ser = serializedAST(db)
    print ser.genSerilizedAST(ast_root)
    