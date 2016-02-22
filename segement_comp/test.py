#coding=utf-8
'''
Created on 2016年2月22日

@author: Bert
'''

import sys
sys.path.append("..")

from algorithm.graph import translate_cfg
from openpyxl import load_workbook, Workbook
from algorithm.ast import get_function_node
from py2neo import Graph

if __name__ == "__main__":
    wb = load_workbook("test3.xlsx", read_only=True)
    ws = wb[u'Sheet3']
    
    neo4jdb = Graph("http://localhost:7475/db/data/")
    
    for row in ws.rows:
        src_cfg = translate_cfg(neo4jdb, get_function_node(neo4jdb, row[0].value))
        tar_cfg = translate_cfg(neo4jdb, get_function_node(neo4jdb, row[1].value))
        
        node = len(src_cfg.vs) * len(tar_cfg.vs)
        edge = len(src_cfg.es) * len(tar_cfg.es)
        
        print node, edge