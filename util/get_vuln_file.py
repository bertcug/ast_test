#coding=utf-8
'''
Created on 2016年1月26日
@author: Bert
'''

from db.models import vulnerability_info, get_connection
import os
import shutil

db_conn = get_connection()
if db_conn is None:
    print u"数据库连接失败"
    exit(0)
    
cur = db_conn.cursor()
cur.execute("select * from vulnerability_info")
rets = cur.fetchall()
cur.close()

for ret in rets:
    file = vulnerability_info(ret).vuln_file
    cur_dir = os.path.dirname(__file__)
    path = os.path.join(cur_dir, file[31:])
    os.makedirs(os.path.dirname(path))
    shutil.copyfile(file, path)