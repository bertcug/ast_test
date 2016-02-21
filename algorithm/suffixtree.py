# -*- coding: UTF-8 -*-
import jpype
import os

class suffixtree:
    
    def __init__(self):
        self.classPath=os.path.join(os.path.dirname(os.path.abspath(__file__)), "suffixtree.jar")
        jvmPath = jpype.getDefaultJVMPath()
        
        if jvmPath==None:
            print "Cannot get the Default JVMPath"
            return -1      
        jvmArg = "-Djava.class.path=" + self.classPath
        
        if not jpype.isJVMStarted():           
            jpype.startJVM(jvmPath,jvmArg)
            
        self.Decompose = jpype.JClass("com.syntactic.Decompose")  

    #查找匹配项，找到匹配则返回匹配段，无匹配返回None
    #srcSeri:查找目标序列
    #vulnSeri:漏洞序列
    def search(self, srcSeri,vulnSeri):
        dc = self.Decompose(srcSeri)    
        if dc.exist(vulnSeri): 
            result=self.Decompose.cut_all(vulnSeri)
            #print "The sub tokens with complete Syntax is:" ,result
            if result:
                ret = self.isComplete(result[0:-1])
                if ret:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
        
    def close(self):
        jpype.shutdownJVM()
    
    #判断字串是否完整 完整返回True否则返回False
    #tokenSeri待判断字串
    def isComplete(self,tokenSeri):
        r = self.Decompose.isComplete(tokenSeri)
        if r == 1:
            #print "tokenSeri is a complete syntax unit"
            return True
        else:
            #print "tokenSeri is not a complete syntax unit"
            return False
#路径根据实际情况修改
#x=suffixtree()

#print x.search("B(1);A(2);A(1);N(3);N(1);A(1)","A(3);N(0);N(1)")
#print x.search("B(1);A(2);A(1);N(3);N(1);Ab(1)","N(1);A(2);A(1)")
#x.close()
