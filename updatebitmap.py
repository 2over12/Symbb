import string
import sys
import signal
import pickle
from triton  import *
from pintool import *
import os
import json


def finished():
    with open('bitmap.json', 'w') as f:
        json.dump(afterIns.bitmap, f)
def afterIns(inst):
    if inst.isBranch:
            if getConcreteRegisterValue(REG.RIP)^afterIns.prevLoc in afterIns.bitmap:
                afterIns.bitmap[getConcreteRegisterValue(REG.RIP)^afterIns.prevLoc]=+1
            else:
                afterIns.bitmap[getConcreteRegisterValue(REG.RIP)^afterIns.prevLoc]=1
            afterIns.prevLoc=getConcreteRegisterValue(REG.RIP)>>1
if __name__=='__main__':
    cwd = os.getcwd()
    print cwd
    setArchitecture(ARCH.X86_64)
    startAnalysisFromSymbol('main')
    insertCall(afterIns,INSERT_POINT.AFTER)
    insertCall(finished,INSERT_POINT.FINI)
    print "here"
    afterIns.prevLoc=0
    afterIns.bitmap=dict()
    with open('bitmap.json') as f:
        afterIns.bitmap = json.load(f)
    runProgram()

    #save_obj(afterIns.bitmap,"bitmap")
    #print afterIns.bitmap
                #print str(beforeIns.bitmap)
