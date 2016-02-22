#coding=utf-8

import sys
sys.path.append("..")

from py2neo import Graph
from openpyxl import Workbook

from algorithm.ast import get_function_node
from algorithm.ast import get_function_ast_root
from algorithm.ast import get_function_return_type
from algorithm.ast import get_function_param_list
from algorithm.ast import get_all_functions
from algorithm.ast import filter_functions
from algorithm.graph import func_cfg_similarity
from algorithm.ast import get_function_node_by_ast_root
from algorithm.ast import get_function_file
from db.models import get_connection
from db.models import vulnerability_info

def func_similarity_cfg_level(db1, funcs, db2, func_name, worksheet):
    # @db1 待比对数据库
    # @db2 漏洞特征数据库
    # @func_name 目标函数名
    
    #过滤一下
    ast_root = get_function_ast_root(db2, func_name)
    return_type = get_function_return_type(db2, ast_root)  # 获取目标函数返回值类型
    param_list = get_function_param_list(db2, ast_root)  # 获取目标函数参数类型列表

    filter_funcs = filter_functions(db1, funcs, return_type, param_list) # 过滤待比较函数
    tar_func = get_function_node(db2, func_name)
    
    for ast_root in filter_funcs:
        src_func = get_function_node_by_ast_root(db1, ast_root)
        
        
        match, simi = func_cfg_similarity(src_func, db1, tar_func, db2)
        if match:
            
            file = get_function_file(db1, src_func.properties[u'name'])[41:]
            worksheet.append(
                             (func_name, file, src_func.properties[u'name'],match,
                              round(simi,4) ))
        elif simi == -1:
            print u"节点太多，未进行比较 "

def cfg_comp_proc():
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
        
    wb = Workbook()
    ws = wb.active
    ws.title = u"CFG函数级漏洞查找测试结果"
    header = [u'漏洞函数名', u"漏洞文件", u"漏洞函数", u"是否匹配", u"相似度", u"耗时"]
    ws.append(header)
    wb.save("cfg_func.xlsx")
    
    all_funcs = get_all_functions(db2)
    for name in func_names:
        try:
            func_similarity_cfg_level(db1, all_funcs, db2, name, ws)
            wb.save("ast_func.xlsx")
        except:
            print "error occured"        
        
if __name__ == "__main__":
    cfg_comp_proc()     