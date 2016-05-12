# coding=utf-8
'''
Created on 2015年11月6日

@author: Bert
'''

def get_function_node(neo4j_db, name_or_id):
    if isinstance(name_or_id, basestring):
        query = "match (n {type:'Function', name:'%s'}) return n" % name_or_id
        records = neo4j_db.cypher.execute(query)    
        return records.one
    else:
        query = "start n=node(%d) return n" % name_or_id
        records = neo4j_db.cypher.execute(query)    
        return records.one

def get_function_ast_root(neo4j_db, name_or_node_or_id):
    if isinstance(name_or_node_or_id, basestring):
        query = "match (n {type:'Function', name:'%s'})-[:`IS_FUNCTION_OF_AST`]->(m) return m" % name_or_node_or_id
        records = neo4j_db.cypher.execute(query)
        return records.one
    elif isinstance(name_or_node_or_id, int):
        query = "start n=node(%d) match (n)-[:`IS_FUNCTION_OF_AST`]->(m) return m" % name_or_node_or_id
        records = neo4j_db.cypher.execute(query)
        return records.one
    else:
        query = "start n=node(%d) match (n)-[:`IS_FUNCTION_OF_AST`]->(m) return m" % name_or_node_or_id._id
        records = neo4j_db.cypher.execute(query)
        return records.one

def get_function_file(neo4j_db, name_or_node):
    if isinstance(name_or_node, basestring):
        query = "match (n {type:'Function', name:'%s'})<-[:`IS_FILE_OF`]-(m) return m" % name_or_node
        records = neo4j_db.cypher.execute(query)
        if records:
            return records.one.properties['filepath']
        else:
            return None
    else:
        query = "start n=node(%d) match (n)<-[:`IS_FILE_OF`]-(m) return m" % name_or_node._id
        records = neo4j_db.cypher.execute(query)
        if records:
            return records.one.properties['filepath']
        else:
            return None
        
def get_in_node(neo4j_db, node, edge_property=None):
    query = ""
    if edge_property is None:
        query = "start n=node(%d) match (m)-->(n) return m" % node._id
    else:
        query = "start n=node(%d) match (m)-[:`%s`]->(n) return m" % (node._id, edge_property)
    
    records = neo4j_db.cypher.execute(query)
    return records.one

def get_out_nodes(neo4j_db, node, edge_property=None):
    query = ""
    if edge_property is None:
        query = "start n=node(%d) match (n)-->(m) return m order by m.childNum" % node._id
    else:
        query = "start n=node(%d) match (n)-[:`%s`]->(m) return m order by m.childNum" % (node._id, edge_property)
    
    records = neo4j_db.cypher.execute(query)
    
    nodes = []
    for record in records:
        nodes.append(record[0])
    
    return nodes

def get_out_node_property_by_type(neo4j_db, node, type, property_name):
    query = "start n=node(%d) match (n)-[:`IS_AST_PARENT`]->(m {type:'%s'}) return m.%s" % (node._id, type, property_name)
    records = neo4j_db.cypher.execute(query)
    return records.one
 
def get_function_return_type(neo4j_db, ast_root_node):
    # @func_ast_node 函数ast树的根结点
    query = "start ast_root=node(%d) match(ast_root)-[:`IS_AST_PARENT`]->(m {type:'ReturnType'}) return m.code" % ast_root_node._id
    records = neo4j_db.cypher.execute(query)
    return records.one

def get_function_param_list(neo4j_db, ast_root_node):
    query = '''start ast_root=node(%d) match(ast_root)-[:`IS_AST_PARENT`]->
    (param_list {type:'ParameterList'})-->(param {type:'Parameter'})-->
    (param_type {type:'ParameterType'}) return param_type.code
    ''' % ast_root_node._id
    records = neo4j_db.cypher.execute(query)
    
    if records:
        types = []
        for record in records:
            types.append(record[0])
        return types
    else:
        return [u'void']

def get_all_functions(neo4j_db):
    query = "match (n {type:'Function'}) return n"
    records = neo4j_db.cypher.execute(query)
    
    func_nodes = []
    for record in records:
        func_nodes.append(record[0])
    return func_nodes

def filter_functions(neo4jdb, funcs, return_type, param_list):
    # @neo4jdb 待过滤函数所在数据库
    # @funcs 待过滤函数集合
    # @return_type 目标函数的返回值类型
    # @param_list 目标函数的参数类型列表
    func_list = []
    
    for func in funcs:
        query = "start n=node(%d) match (n)-[:`IS_FUNCTION_OF_AST`]->(m) return m" % func._id
        ast_root_node = neo4jdb.cypher.execute(query).one   # 肯定可以找到这个函数，而且唯一
        
        # filter by return type and param list
        ret_type = get_function_return_type(neo4jdb, ast_root_node)
        prm_list = get_function_param_list(neo4jdb, ast_root_node)
        
        if ret_type == return_type and prm_list == param_list:
            func_list.append(ast_root_node)
    
    return func_list

def get_function_node_by_ast_root(neo4jdb, ast_root):
    query = "start m=node(%d) match(n)-[:`IS_FUNCTION_OF_AST`]->(m) return n" % ast_root._id
    ret = neo4jdb.cypher.execute(query).one
    return ret

class serializedAST:
       
    def __init__(self, neo4jdb):
        # @data_type_mapping: True:相同类型变量映射成相同token， False：所有类型变量映射成相同token
        # @const_mapping: True:相同常亮映射到相同token，所有常量映射成相同token
        self.neo4jdb = neo4jdb
        self.variable_maps = {'other':'v'}  # 变量与类型映射表
    
    #获取父节点   
    def getParent(self, node):
        return get_in_node(self.neo4jdb, node, edge_property='IS_AST_PARENT')
    
    # 处理Identifier节点
    def parseIndentifierNode(self, node):
        parent = self.getParent(node)
        if parent:
            node_type = parent.properties['type']  # 根据父节点类型进行判断
            
            if "Callee" == node_type:  # 函数类型
            	c = node.properties['code']
                return (["f(0)",], ["f(0)",], ["f(0)",], ["f(0)",], ["%s(0)" % c,] ) # 默认Identifier没有子节点
            
            elif "Lable" == node_type:  # Lable不进行映射
                return (["Identifier(0)",], ["Identifier(0)",], ["Identifier(0)",], ["Identifier(0)",], ["Identifier(0)",])
            
            elif "GotoStatement" == node_type:  # goto语句的lable也不映射
                return (["Identifier(0)",], ["Identifier(0)",], ["Identifier(0)",], ["Identifier(0)",], ["Identifier(0)",])
            
            else:
                #获取变量类型
                code = node.properties['code']
                var_type = ""
                if code in self.variable_maps:
                    var_type = self.variable_maps[code]
                else:
                    var_type = self.variable_maps['other']
                
                return (["%s(0)" % var_type,], ["%s(0)" % var_type,], ["v(0)",], ["v(0)",], ["%s(0)" % code,])
                    
        else:
            print "Error"
            return None
    
    # 处理ParamList节点,建立参数名与参数类型映射表
    def parseParamListNode(self, node):
        nodes = get_out_nodes(self.neo4jdb, node, edge_property='IS_AST_PARENT')
        
        if nodes:
            for n in nodes:
                variable = get_out_node_property_by_type(self.neo4jdb, n, 'Identifier', 'code')
                var_type = get_out_node_property_by_type(self.neo4jdb, n, 'ParameterType', 'code')
                self.variable_maps[variable] = var_type
    
    # 处理变量声明语句：
    def parseIdentifierDeclNode(self, node):
        # 获取变量名和变量类型
        variable = get_out_node_property_by_type(self.neo4jdb, node, 'Identifier', 'code')
        var_type = get_out_node_property_by_type(self.neo4jdb, node, 'IdentifierDeclType', 'code')
        self.variable_maps[variable] = var_type

    # 处理常量
    def parsePrimaryExprNode(self, node):
        const_code = node.properties['code']
        return (["%s(0)" % const_code,], ["c(0)",], ["%s(0)" % const_code,], ["c(0)"],["%s(0)" % const_code,])
        
    # 类型映射，解决指针与数组、多维数组问题
    def parseType(self, data_type):
        return data_type  # 简单处理
           
    def genSerilizedAST(self, root):
        # @return: 返回 tuple, 分别代表 区分变量及常量  区分变量不区分常量 区分常量不区分变量 不区分变量和常量
        # @root:  function ast root node
        
           
        # AST节点之间以 IS_AST_PARENT 边连接
        res = get_out_nodes(self.neo4jdb, root, edge_property='IS_AST_PARENT')
        
        if res:  # 如果有子节点
            s_ast = ([], [], [], [], [])  # 存储子节点产生的序列化AST字符串
            
            # 处理子节点
            for r in res:  # 认为子节点按照childrenNum排序
                
                if r.properties['type'] == "ReturnType":
                    continue
                
                elif r.properties['type'] == "ParameterList":
                    self.parseParamListNode(r)
                    continue
                
                elif r.properties['type'] == "IdentifierDecl":
                    self.parseIdentifierDeclNode(r)
                    
                ret = self.genSerilizedAST(r)  # 递归调用
                s_ast = (s_ast[0] + ret[0], s_ast[1] + ret[1], 
                        s_ast[2] + ret[2], s_ast[3] + ret[3], s_ast[4]+ret[4] )
                                                
            # 处理根节点
            t = root.properties['type']
            
            if (t == 'AdditiveExpression' or t == 'AndExpression' or t == 'AssignmentExpr'
                or  t == 'BitAndStatement' or t == 'EqualityExpression' or t == 'ExclusiveOrExpression'
                or t == 'InclusiveOrExpression' or t == 'MultiplicativeExpression' 
                or t == 'OrExpression' or t == 'RelationalExpression' or t == 'ShiftStatement'):
                
                root_ast = [root.properties['operator'] + "(%d)" % len(s_ast[0]),]
                s_ast=( 
                	root_ast + s_ast[0], 
                	root_ast + s_ast[1],
                    root_ast + s_ast[2], 
                    root_ast + s_ast[3],
                    root_ast + s_ast[4] )
            else:    
                root_ast = [ root.properties['type'] + "(%d)" % len(s_ast[0]), ]
                s_ast =  ( 
                	root_ast+s_ast[0], 
                	root_ast+s_ast[1],
                    root_ast+s_ast[2], 
                    root_ast+s_ast[3], 
                    root_ast+s_ast[4] )                      
            
            return s_ast
        
        else:  # 处理孤立节点
            t = root.properties['type']
            
            if t == 'IncDec':
                s_ast = ( 
                	[root.properties['code'] + "(0)",], 
                	[root.properties['code'] + "(0)",],
                    [root.properties['code'] + "(0)",], 
                    [root.properties['code'] + "(0)",], 
                    [root.properties['code'] + "(0)",] 
                    )
                return s_ast
        
            elif t == 'CastTarget' or t == 'UnaryOperator':
                s_ast = ( 
                	[root.properties['code'] + "(0)",],
                	[root.properties['code'] + "(0)",],
                    [root.properties['code'] + "(0)",],
                    [root.properties['code'] + "(0)",],
                    [root.properties['code'] + "(0)",] 
                    )
                return s_ast
            
            elif t == 'SizeofOperand':
                code = root.properties['code']
                var_type = ""
                
                if code in self.variable_maps:
                    var_type = self.variable_maps[code]
                else:
                    var_type = self.variable_maps['other']

                s_ast = ( 
                	[var_type + "(0)",],
                	[var_type + "(0)",],
                	[var_type + "(0)",],
                	[var_type + "(0)",],
                	[code + "(0)",]
                	)
                return s_ast
            
            elif t == 'Identifier':
                return self.parseIndentifierNode(root)
            
            elif(t == 'PrimaryExpression'):
                return self.parsePrimaryExprNode(root)
                               
            else:
                s_ast = ( 
                	[root.properties['type'] + "(0)",],
                	[root.properties['type'] + "(0)",],
                    [root.properties['type'] + "(0)",],
                    [root.properties['type'] + "(0)",],
                    [root.properties['type'] + "(0)",],
                     )
                return s_ast