#coding=utf-8
import time

def func_similarity_astLevel(db1, funcs, db2, func_name):
    # @db1 待比对数据库
    # @db2 漏洞特征数据库
    # @func_name 目标函数名
    
    start_time = time.time()
    
    target_func = getASTRootNodeByName(func_name, db2)
    return_type = getFuncRetType(target_func, db2)  # 获取目标函数返回值类型
    param_list = getFuncParamList(target_func, db2)  # 获取目标函数参数类型列表
    
    # funcs = getAllFuncs(db1) #获取所有函数
    filter_funcs = filterFuncs(db1, funcs, return_type, param_list)  # 过滤待比较函数
    
    pattern1 = serializedAST(db2, True, True).genSerilizedAST(target_func)
    pattern2 = serializedAST(db2, False, True).genSerilizedAST(target_func)  # 所有类型变量映射成相同值
    pattern3 = serializedAST(db2, True, False).genSerilizedAST(target_func)
    pattern4 = serializedAST(db2, False, False).genSerilizedAST(target_func)
    
    s1 = serializedAST(db1, True, True)
    s2 = serializedAST(db1, False, True)
    s3 = serializedAST(db1, True, False)
    s4 = serializedAST(db1, False, False)
    
    report_dict = {}
    for func in filter_funcs:
        report = ast_match_info()
        
        if pattern1 == s1.genSerilizedAST(func):
            report.distinct_type_and_const = True
        
        if pattern2 == s2.genSerilizedAST(func):
            report.distinct_const_no_type = True
        
        if pattern3 == s3.genSerilizedAST(func):
            report.distinct_type_no_const = True
        
        if pattern4 == s4.genSerilizedAST(func):
            report.no_type_no_const = True
            
        if report.is_valid():
            report_dict[func] = pickle.dumps(report)
    
    end_time = time.time()
    cost = end_time - start_time
    return report_dict, round(cost, 2)