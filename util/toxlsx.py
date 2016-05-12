# coding=utf-8
from openpyxl import Workbook
import sqlite3
import argparse
def export_xlsx(db, out_file):
	db = sqlite3.connect(db)
	ret = db.execute("SELECT name FROM sqlite_master WHERE type='table' order by name")
	wb = Workbook()
	for table in ret.fetchall():
		ws = wb.create_sheet()
		ws.title = table[0]
		ret = db.execute("select * from %s" % table)
		for r in ret:
			ws.append(r)
	
	wb.save(out_file)

if __name__ == "__main__":
	parse = argparse.ArgumentParser()
	parse.add_argument("db", help="database")
	parse.add_argument("outfile", help="file place")
	
	args=parse.parse_args()
	
	export_xlsx(args.db, args.outfile)
