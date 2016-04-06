#coding=utf-8
import sys
sys.path.append("..")

from py2neo import Graph
from openpyxl import Workbook

from algorithm.ast import get_function_node
from algorithm.ast import get_all_functions
from algorithm.graph import func_cfg_similarity
from algorithm.ast import get_function_file

def func_similarity_segement_level(db1, funcs, db2, func_name, worksheet):
    # @db1 待比对数据库
    # @db2 漏洞特征数据库
    # @func_name 目标函数名
    
    tar_func = get_function_node(db2, func_name)
    for src_func in funcs: 
        match, simi = func_cfg_similarity(src_func, db1, tar_func, db2)
        if match:
            
            file = get_function_file(db1, src_func.properties[u'name'])[41:]
            worksheet.append(
                             (func_name, file, src_func.properties[u'name'],match,
                              round(simi,4) ))
        elif simi == -1:
            print u"节点太多，未进行比较 "

def segement_comp_proc():
    db1 = Graph("http://localhost:7475/db/data/")  #假设软件数据库开启在7475端口
    db2 = Graph("http://localhost:7476/db/data/")  #假设代码段数据库开启在7476
    
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = u"CFG代码段查找测试结果"
    header = [u'代码段', u"漏洞文件", u"漏洞函数", u"是否匹配", u"相似度"]
    worksheet.append(header)
    workbook.save("cfg_segement.xlsx")
    
    #假设只测试一个代码段函数
    segement_funcs = ["CVE_2015_3417_VULN_COMPLETE_0",]
    funcs = get_all_functions(db1)
    
    for func_name in segement_funcs:
        try:
            func_similarity_segement_level(db1, funcs, db2, func_name, worksheet)
            workbook.save("cfg_segement.xlsx")
        except:
            print "error occured!"
    
    print "all works done!"
