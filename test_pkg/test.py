#coding=utf-8
'''
Created on 2016年3月28日

@author: Bert
'''
import sys
sys.path.append("..")
import datetime
import re
from algorithm.ast import serializedAST, get_function_ast_root,get_function_node_by_ast_root
from algorithm.graph import func_cfg_similarity
from openpyxl import load_workbook, Workbook
from algorithm.suffixtree import suffixtree
from py2neo import Graph

def search_vuln_seg_in_patched(db1, vuln_seg, db2, patched_name, suffix_obj, worksheet):
    
    print "[%s] processing %s VS %s" % (
                                   datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"),
                                   vuln_seg, patched_name)
    
    vuln_seg_func = get_function_ast_root(db1, vuln_seg)
    if vuln_seg_func is None:
        print "%s is not found" % vuln_seg
        worksheet.append( (vuln_seg, patched_name, "vuln_not_found","-", "-","-", "-","-","-") )
    
    patched_func = get_function_ast_root(db2, patched_name)
    if patched_func is None:
        print "%s is not found" % patched_name
        worksheet.append( (vuln_seg, patched_name, "patch_not_found","-", "-", "-", "-","-","-") )
    
    #序列化AST返回值是一个数组，0元素是序列化的AST字符串，1元素是节点个数，AST字符串以;结尾，需要去掉结尾的;
    pattern1 = serializedAST(db1, True, True).genSerilizedAST(vuln_seg_func)[0][:-1]
    pattern2 = serializedAST(db1, False, True).genSerilizedAST(vuln_seg_func)[0][:-1] 
    pattern3 = serializedAST(db1, True, False).genSerilizedAST(vuln_seg_func)[0][:-1]
    pattern4 = serializedAST(db1, False, False).genSerilizedAST(vuln_seg_func)[0][:-1]
    
    #delete FunctionDef and CompoundStatement node
    prefix_str = r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);"
    pattern1 = re.sub(prefix_str, "", pattern1)
    pattern2 = re.sub(prefix_str, "", pattern2)
    pattern3 = re.sub(prefix_str, "", pattern3)
    pattern4 = re.sub(prefix_str, "", pattern4)
    
    s1 = serializedAST(db2, True, True).genSerilizedAST(patched_func)[0][:-1]
    s2 = serializedAST(db2, False, True).genSerilizedAST(patched_func)[0][:-1]
    s3 = serializedAST(db2, True, False).genSerilizedAST(patched_func)[0][:-1]
    s4 = serializedAST(db2, False, False).genSerilizedAST(patched_func)[0][:-1]
    
    report = {}
    if suffix_obj.search(s1, pattern1):
        report['distinct_type_and_const'] = True
    else:
        report['distinct_type_and_const'] = False
        
    if suffix_obj.search(s2, pattern2):
        report['distinct_const_no_type'] = True
    else:
        report['distinct_const_no_type'] = False
        
    if suffix_obj.search(s3, pattern3):
        report['distinct_type_no_const'] = True
    else:
        report['distinct_type_no_const'] = False
        
    if suffix_obj.search(s4, pattern4):
        report['no_type_no_const'] = True
    else:
        report['no_type_no_const'] = False
    
    #begin cfg
    patch_root = get_function_node_by_ast_root(db2, patched_func)
    vuln_seg_root = get_function_node_by_ast_root(db1, vuln_seg_func)
    match, simi = func_cfg_similarity(patch_root, db2, vuln_seg_root, db1)
    
    worksheet.append( (vuln_seg, patched_name, "success", report["distinct_type_and_const"],
                       report["distinct_const_no_type"], report["distinct_type_no_const"],
                       report['no_type_no_const'], match, simi) )
    
def main():
    data = load_workbook("Wireshark.xlsx", read_only=True)[u'Sheet3']
    suffix_obj = suffixtree()
    
    wb = Workbook()
    ws = wb.active
    
    db1 = Graph("http://127.0.0.1:7476/db/data/")
    db2 = Graph()
    
    for row in data.rows:
        vuln_seg = row[0].value
        patched_name = vuln_seg[:14] + "PATCHED_" + row[2].value
        
        try:
            search_vuln_seg_in_patched(db1, vuln_seg, db2, patched_name, suffix_obj, ws)
            wb.save("result.xlsx")
        except Exception as e:
            print e
    
    suffix_obj.close()
    print "all works done"

if __name__ == "__main__":
    main()
        
    
    