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
from segement_comp import get_type_mapping_table

def search_vuln_seg_in_patched(db1, vuln_seg, db2, patched_name, suffix_obj, worksheet):
    
    print "[%s] processing %s VS %s" % (
                                   datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"),
                                   vuln_seg, patched_name)
    
    vuln_seg_func = None
    try:
        vuln_seg_func = get_function_ast_root(db1, vuln_seg)
    except:
        vuln_seg_func = get_function_ast_root(db1, patched_name[22:])
        vuln_seg = patched_name[22:]
        
    if vuln_seg_func is None:
        print "%s is not found" % vuln_seg
        worksheet.append( (vuln_seg, patched_name, "vuln_not_found","-", "-","-", "-","-","-") )
        return
    
    patched_func = get_function_ast_root(db2, patched_name)
    if patched_func is None:
        print "%s is not found" % patched_name
        worksheet.append( (vuln_seg, patched_name, "patch_not_found","-", "-", "-", "-","-","-") )
        return
    
    o1 = serializedAST(db1, True, True)
    o2 = serializedAST(db1, False, True)
    o3 = serializedAST(db1, True, False)
    o4 = serializedAST(db1, False, False)
    
    type_mapping = get_type_mapping_table(db2, patched_name)
    
    o1.variable_maps = type_mapping
    o2.variable_maps = type_mapping
    o3.variable_maps = type_mapping
    o4.variable_maps = type_mapping
    
    #序列化AST返回值是一个数组，0元素是序列化的AST字符串，1元素是节点个数，AST字符串以;结尾，需要去掉结尾的;
    pattern1 = o1.genSerilizedAST(vuln_seg_func)[0][:-1]
    pattern2 = o2.genSerilizedAST(vuln_seg_func)[0][:-1] 
    pattern3 = o3.genSerilizedAST(vuln_seg_func)[0][:-1]
    pattern4 = o4.genSerilizedAST(vuln_seg_func)[0][:-1]
    
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
    
def wireshark_diff():
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
            wb.save("wireshark_diff.xlsx")
        except Exception as e:
            print e
    
    suffix_obj.close()
    print "wireshark all works done"
    
def ffmpeg_diff():
    data = load_workbook("ffmpeg.xlsx", read_only=True)[u'Sheet3']
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
            wb.save("ffmpeg_diff.xlsx")
        except Exception as e:
            print e
    
    suffix_obj.close()
    print "ffmpeg all works done"

def get_segements(segements, patch_func_name):
    cveid = patch_func_name[0:13]
    ret = []
    for segement in segements:
        if segement.startswith(cveid):
            ret.append(segement)
    return ret    

def code_reuse():
    wb = load_workbook("data.xlsx")
    
    wireshark_segement_list = []
    for row in wb['wireshark'].rows:
        wireshark_segement_list.append(row[0].value)
    ffmpeg_segement_list = []
    for row in wb['ffmpeg'].rows:
        ffmpeg_segement_list.append(row[0].value)
    
    db = Graph("http://127.0.0.1:7476/db/data/")
    suffix_obj = suffixtree()
    #wireshark
    result = Workbook()
    ws = result.create_sheet("wireshark_test",0)
    for row in wb['Sheet2'].rows:
        test_list = get_segements(wireshark_segement_list, row[0].value)
        for test in test_list:
            try:
                search_vuln_seg_in_patched(db, test, db, row[0].value, suffix_obj, ws)
                result.save("code_reuse.xlsx")
            except Exception as e:
                print e
        
    #ffmpeg
    ff_ws = result.create_sheet("ffmpeg_test",1)
    for row in wb['Sheet1'].rows:
        test_list = get_segements(ffmpeg_segement_list, row[0].value)
        for test in test_list:
            try:
                search_vuln_seg_in_patched(db, test, db, row[0].value, suffix_obj, ws)
                result.save("code_reuse.xlsx")
            except Exception as e:
                print e  
    suffix_obj.close()
    print "code reuse all works done"
      
if __name__ == "__main__":
    arg = sys.argv[1]
    if arg == "wireshark":
        wireshark_diff()
    elif arg == "ffmpeg":
        ffmpeg_diff()
    elif arg == "reuse":
        code_reuse() 
    else:
        print "argument error"
    
    