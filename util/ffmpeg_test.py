# coding=utf-8
import sys
sys.path.append("..")

from algorithm.suffixtree import suffixtree
from openpyxl import Workbook
import sqlite3
import os, re
import argparse
import datetime

def get_ffmpeg_segements():
	db = sqlite3.connect("/home/bert/Documents/data/all_funcs.db")
	ret = db.execute("select * from ffmpeg_segement")
	segements = []
	for r in ret.fetchall():
		segements.append(r[0])
	return segements

def get_ffmpeg_funcs(softdb):
	soft_db = sqlite3.connect(softdb)
	table_name = os.path.basename(softdb)[:-3]
	ret = soft_db.execute("select * from %s" % table_name)
	return ret

def ffmpeg_test(softdb):
	segements = get_ffmpeg_segements()
	soft_funcs = get_ffmpeg_funcs(softdb)

	suffixtree_obj = suffixtree()
	wb = Workbook()
	ws = wb.active

	func_db = sqlite3.connect("/home/bert/Documents/data/all_funcs.db")

	for func in soft_funcs:

		for seg in segements:
			ret = func_db.execute("select * from all_funcs where func_name='%s'" % seg)
			seg_ast = ret.fetchone()

			seg_ast1 = re.sub(r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);", "", seg_ast[4])
			seg_ast2 = re.sub(r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);", "", seg_ast[5])
			seg_ast3 = re.sub(r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);", "", seg_ast[6])
			seg_ast4 = re.sub(r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);", "", seg_ast[7])
			seg_ast5 = re.sub(r"^FunctionDef\([0-9]+\);CompoundStatement\([0-9]+\);", "", seg_ast[8])

			print "[%s] processing %s VS %s" % (
                                   datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S"),
                                   seg, func[1])
			try:
				ast1_ret = suffixtree_obj.search(func[4], seg_ast1)
				ast2_ret = suffixtree_obj.search(func[5], seg_ast2)
				ast3_ret = suffixtree_obj.search(func[6], seg_ast3)
				ast4_ret = suffixtree_obj.search(func[7], seg_ast4)
				ast_nomap = suffixtree_obj.search(func[8], seg_ast5) #nomap

				if ast1_ret or ast2_ret or ast3_ret or ast4_ret or ast_nomap:
					line = (seg, func[1], func[0], func[2], ast1_ret, ast2_ret, ast3_ret, ast4_ret, ast_nomap)
					ws.append(line)
					wb.save(os.path.basename(softdb)[:-3] + ".xlsx")
			except Exception,e:
				print e
	wb.save(os.path.basename(softdb)[:-3] + ".xlsx")
		
	print "all works done"

if __name__ == "__main__":
	parse = argparse.ArgumentParser()
	parse.add_argument("softdb", help="sqlite db path")
	args = parse.parse_args()

	ffmpeg_test(args.softdb)
