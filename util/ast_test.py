from py2neo import Graph

def get_all_functions(neo4j_db):
    query = "match (n {type:'Function'}) return n"
    records = neo4j_db.cypher.execute(query)
    
    func_nodes = []
    for record in records:
        func_nodes.append(record[0])
    return func_nodes

if __name__ == "__main__":
	db = Graph("http://localhost:7475/db/data/")
	funcs = get_all_functions(db)
	print funcs
