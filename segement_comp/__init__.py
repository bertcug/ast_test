#coding=utf-8

import sys
sys.path.append("..")

from algorithm.ast import get_function_ast_root, serializedAST

def get_type_mapping_table(neo4j_db, func_name):
    ast_root = get_function_ast_root(neo4j_db, func_name)
    if ast_root is None:
        print u"节点不存在"
        return {'other':'v'}
    else:
        ser = serializedAST(neo4j_db)
        ser.genSerilizedAST(ast_root)
        return ser.variable_maps
    