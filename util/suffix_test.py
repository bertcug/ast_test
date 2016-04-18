# -*- encoding:utf-8 -*-
import sys
sys.path.append("..")

from algorithm.suffixtree import suffixtree


if __name__ == "__main__":
    
    obj = suffixtree()
    lines = open("CVE-2013-0844_VULN_COMPLETE_0.c", "r").readlines()
    print obj.search(lines[0], lines[1])
    
    lines = open("CVE-2013-0868_VULN_COMPLETE_1.c", "r").readlines()
    print obj.search(lines[0], lines[1])
    
    obj.close()