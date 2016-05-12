# coding=utf-8
import sys
sys.path.append("..")

from ast import serializedAST, get_function_ast_root
from py2neo import Graph
import argparse

if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    parse.add_argument("-f", "--func", help="function name")
    parse.add_argument("-p", "--port", type=int, help="db port")
    args = parse.parse_args()
    
    func = args.func
    db = Graph("http://127.0.0.1:%d/db/data/" % args.port)
    ast_root = get_function_ast_root(db, func)

    ser = serializedAST(db)
    ret =  ser.genSerilizedAST(ast_root)
    print "First:", ";".join(ret[0])
    print "Second:", ";".join(ret[1])
    print "Third:", ";".join(ret[2])
    print "Fourth:", ";".join(ret[3])
    print "no mapping:", ";".join(ret[4])