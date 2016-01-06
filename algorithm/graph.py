# coding=utf-8
'''
Created on 2015年11月9日
@author: Bert
'''

from igraph import Graph

def get_cfg_nodes(neo4j_db, function_node):
    query = "match (n {functionId:%d, isCFGNode:'True'}) return n" % function_node._id
    records = neo4j_db.cypher.execute(query)
   
    nodes = []
    for record in records:
        nodes.append(record[0])
    
    return nodes

def get_cfg_edges(neo4j_db, function_node):
    query = "match (n {functionId:%d, isCFGNode:'True'})-[e:`FLOWS_TO`]->(m) return e"\
             % function_node._id
    records = neo4j_db.cypher.execute(query)
    
    edges = []
    for record in records:
        edges.append(record[0])
    
    return edges


def get_ddg_edges(neo4j_db, function_node):
    query = "match(n {functionId:%d, isCFGNode:'True'})-[e:`REACHES`]->(m) return e"\
             % function_node._id
    records = neo4j_db.cypher.execute(query)
    
    edges = []
    for record in records:
        edges.append(record[0])
    
    return edges

def get_cdg_edges(neo4j_db, function_node):
    query = "match(n {functionId:%d, isCFGNode:'True'})-[e:`CONTROLS`]->(m) return e"\
             % function_node._id
    records = neo4j_db.cypher.execute(query)
    
    edges = []
    for record in records:
        edges.append(record[0])
    
    return edges

def get_func_file(neo4j_db, function_node):
    query = "start n=node(%d) match (m {type:'File'})-[:`IS_FILE_OF`]->(n) return m.filepath" % function_node._id
    records = neo4j_db.cypher.execute(query)
    return records.one

def get_node_properties(dict):
    properties = {}
    if dict['code'] is None:
        properties['code'] = "None"
    else:
        properties['code'] = dict['code']
    
    if dict['type'] is None:
        properties['type'] = "None"
    else:
        properties['type'] = dict['type']
    return properties

def get_edge_properties(dict):
    if dict['flowLabel'] is None:
        return {'flowLabel':"None"}
    else:
        return {'flowLabel':dict['flowLabel']}
    
def translate_cfg(neo4j_db, function_node):
    cfg_edges = get_cfg_edges(neo4j_db, function_node)
    
    #create igraph cfg
    g = Graph(directed = True)
    
    #add edge and edge properties
    for edge in cfg_edges :
        start_node = edge.start_node
        end_node = edge.end_node
        
        if start_node is None or end_node is None:
            print "edge has no start or end node"
        
        try:
            g.vs.find(name=str(start_node._id))
        except:
            g.add_vertex(name=str(start_node._id), **get_node_properties(start_node.properties))
        try:
            g.vs.find(name=str(end_node._id))
        except:
            g.add_vertex(name=str(end_node._id), **get_node_properties(end_node.properties))
        
        g.add_edge(str(start_node._id), str(end_node._id),**get_edge_properties(edge.properties))
    
    return g

def node_compat_fn(g1,g2,n1,n2):
    if g1.vs[n1]['type']==g2.vs[n2]['type'] :
        return True
    else:
        return False

def edge_compat_fn(g1,g2,e1,e2):
    if g1.es[e1]['flowLabel'] == g2.es[e2]['flowLabel'] :
        return True
    else:
        return False
    
def cal_similarity(srcCFG,tarCFG,vertexMap):
    count = 0
    sum = 0
    if vertexMap:
        sum = len(vertexMap)
    for i in range(sum) :
        if srcCFG.vs[vertexMap[i]]['code'] == tarCFG.vs[i]['code'] :
            count +=1
    return round((float(count)/float(sum)), 2)

def func_cfg_similarity(func1, db1, func2, db2):
    srcCFG = translate_cfg(db1, func1)
    targetCFG = translate_cfg(db2, func2)
    ret = srcCFG.get_subisomorphisms_vf2(other = targetCFG,node_compat_fn = node_compat_fn,
                                         edge_compat_fn = edge_compat_fn)
    if len(ret) == 0:
        return False, 0
    else:
        rs = []
        for r in ret:
            rs.append(cal_similarity(srcCFG, targetCFG, r))
        
        return True, round(max(rs), 4)

 
    
