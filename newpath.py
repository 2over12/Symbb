import string
import sys
import signal
from triton  import *
from pintool import *
from triton.ast import *
import os
import random
import json
#./triton ~/Documents/Symbb/newpath.py ~/fuzzExpat/harness/otest ~/fuzzExpat/harness/note.xml
f = []
def taint(inst):
	if inst.getAddress() == 0x00400c82:
		print ' Symbolizing memory at %#x: %s' %(inst.getAddress(),inst.getDisassembly())
		rsi=getCurrentRegisterValue(REG.RSI)
		memval=getCurrentMemoryValue(rsi)
		index=0
		while memval != 0x00:
			a=convertMemoryToSymbolicVariable(MemoryAccess(rsi+index,CPUSIZE.BYTE,memval))
			#taintMemory(r12+index)
	#
			if not a:
				print "Well shit"
			index=index+1
			memval=getCurrentMemoryValue(rsi+index)

		print str(index)+" bytes symblized"
def finishing():
	with open('bitmap.json','w') as fp:
	    json.dump(afterIns.bitmap,fp,sort_keys=True, indent=4)
	#print afterIns.bitmap
def getMemoryString(addr):
    s = str()
    index = 0

    while getConcreteMemoryValue(addr+index):
        c = chr(getConcreteMemoryValue(addr+index))
        if c not in string.printable: c = ""
        s += c
        index  += 1

    return s

def afterIns(inst):
	 if inst.isControlFlow() and inst.getType() not in [OPCODE.RET, OPCODE.JMP, OPCODE.CALL] and (0x0000000000400000 <= inst.getAddress() < 0x000000000062a000):
		 currLoc=getConcreteRegisterValue(REG.RIP)
		 if unicode(currLoc^afterIns.prevLoc) in afterIns.bitmap:
 			 afterIns.bitmap[unicode(currLoc^afterIns.prevLoc)]=+1
 		 else:
 			 afterIns.bitmap[unicode(currLoc^afterIns.prevLoc)]=1;
		 obj=inst.getFirstOperand()
		 nLoc=0
		# print type(obj)
		 if type(obj) is type(MemoryAccess(1,1,1)):
			 nLoc=obj.getConcreteValue() #check if this is the right value
		 else:
			 if type(obj) is type(Immediate(0x2,0x2)):
				 nLoc=obj.getValue()
			 else:
				 nLoc=obj.getConcreteValue()

		 if currLoc==nLoc:
			 nLoc=inst.getNextAddress()
		 if unicode(nLoc^afterIns.prevLoc) not in afterIns.bitmap:
			print str(nLoc^afterIns.prevLoc)
			pco=getPathConstraints()
		 	cstr=ast.equal(ast.bvtrue(),ast.bvtrue())
		 	for pc in pco:
			 	if pc.isMultipleBranches():
				 	branches=pc.getBranchConstraints()
				 	for branch in branches:
					 	isPreviousBranchConstraint=branch["isTaken"] and branch["srcAddr"] != inst.getAddress()
					 	isBranchToTake=branch["srcAddr"]==inst.getAddress() and branch["dstAddr"]==nLoc
					 	if isPreviousBranchConstraint or isBranchToTake:
						 	cstr=ast.land(cstr,branch["constraint"])
		 	cstr = ast.assert_(cstr)
			print "starting solve"
			#print cstr
			model = getModel(cstr)
			print model
			solved=str()
			for item in model:
				solved+=chr(model[item].getValue())

			print solved
			r=random.randint(1, 10000000000)
			while str(r) in f:
				r=random.randint(1, 10000000000)
			f.append(str(r))
			file = open("/home/ian/fuzzExpat/out/queue/"+str(r)+"tagged", 'w+')
			file.write(solved)
			file.close()
			print inst
			print hex(nLoc)
			print "Loc"+str(nLoc^afterIns.prevLoc)
			print "finishing solve"
			#do test FIGURE OUT IF SATISFIED
			afterIns.bitmap[unicode(nLoc^afterIns.prevLoc)]=1
		 else:
			 	#print "OMFG:"+str(afterIns.bitmap[nLoc^afterIns.prevLoc])
				afterIns.bitmap[unicode(nLoc^afterIns.prevLoc)]=afterIns.bitmap[unicode(nLoc^afterIns.prevLoc)]+1
				#print "OH:"+str(afterIns.bitmap[nLoc^afterIns.prevLoc])
		 afterIns.prevLoc=currLoc>>1

# Constant folding simplification.
def constantFolding(node):
    if node.isSymbolized():
        return node
    return ast.bv(node.evaluate(), node.getBitvectorSize())

if __name__=='__main__':
	for(dirpath,dirnames,filenames) in os.walk("/home/ian/fuzzExpat/out/queue"):
		f.extend(filenames)
		break
	setArchitecture(ARCH.X86_64)
	#setupImageWhitelist(['libexpat.a'])
	startAnalysisFromAddress(0x00400c82)
    # Align the memory
	enableMode(MODE.ALIGNED_MEMORY, True)
    # Only perform the symbolic execution on the target binary
	#setupImageWhitelist(['otest'])
	insertCall(afterIns,INSERT_POINT.AFTER)
	insertCall(taint,INSERT_POINT.BEFORE_SYMPROC)
	insertCall(finishing,INSERT_POINT.FINI)
	addCallback(constantFolding, CALLBACK.SYMBOLIC_SIMPLIFICATION)
	afterIns.prevLoc=0
	afterIns.bitmap=dict()
	with open('bitmap.json','r') as fp:
	     afterIns.bitmap = json.load(fp)
	print afterIns.bitmap
	runProgram()
	#print str(beforeIns.bitmap)
