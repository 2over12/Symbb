import string
import sys
import signal
from triton  import *
from pintool import *
from triton.ast import *
#./triton ~/Documents/Symbb/newpath.py ~/fuzzExpat/harness/otest ~/fuzzExpat/harness/note.xml
def taint(inst):
	if inst.getAddress() == 0x00401762:
		print ' Symbolizing memory at %#x: %s' %(inst.getAddress(),inst.getDisassembly())
		rsi=getCurrentRegisterValue(REG.RSI)
		memval=getCurrentMemoryValue(rsi)
		index=0
		while memval != 0x00:
			print chr(memval)
			a=convertMemoryToSymbolicVariable(MemoryAccess(rsi+index,CPUSIZE.BYTE,memval))
			#taintMemory(r12+index)
	#
			if not a:
				print "Well shit"
			index=index+1
			memval=getCurrentMemoryValue(rsi+index)

		print str(index)+" bytes symblized"

def getMemoryString(addr):
    s = str()
    index = 0

    while getConcreteMemoryValue(addr+index):
        c = chr(getConcreteMemoryValue(addr+index))
        if c not in string.printable: c = ""
        s += c
        index  += 1

    return s

#def beforeIns(inst):
#	if inst.isBranch:
#		takeSnapshot();
def afterIns(inst):
	 if inst.isBranch():
		# print "right here"
		 #takeSnapshot()
		 #print inst
		 #print hex(inst.getNextAddress())
		 currLoc=getConcreteRegisterValue(REG.RIP)
		 if currLoc^afterIns.prevLoc in afterIns.bitmap:
 			 afterIns.bitmap[currLoc^afterIns.prevLoc]=+1
 		 else:
 			 afterIns.bitmap[currLoc^afterIns.prevLoc]=1;
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
				 print inst
				 print hex(nLoc)

		 if currLoc==nLoc:
			 nLoc=inst.getNextAddress()
		 if nLoc^afterIns.prevLoc not in afterIns.bitmap:
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
			print cstr
			print "starting solve"
			model = getModel(cstr)
		 	print "finishing solve"
		 	print model
			#do test FIGURE OUT IF SATISFIED
			afterIns.bitmap[nLoc^afterIns.prevLoc]=1
		 else:
				afterIns.bitmap[nLoc^afterIns.prevLoc]=+1
		 afterIns.prevLoc=currLoc>>1



		 #if currLoc==0x00401743:
		 #	print hex(currLoc);
		#	print hex(getConcreteRegisterValue(REG.RIP))
		 #a=False
		 #if currLoc^beforeIns.prevLoc in beforeIns.bitmap:
			# beforeIns.bitmap[currLoc^beforeIns.prevLoc]+=1;
			 #print "Bitmap:"+str(beforeIns.bitmap)
		#	 a=True
		# else:
		#	beforeIns.bitmap[currLoc^beforeIns.prevLoc]=1;
		 #for se in inst.getSymbolicExpressions():
		#	if se.isSymbolized() and a:
		#		print '%#x: %s %d' %(inst.getAddress(),inst.getDisassembly(),beforeIns.bitmap[currLoc^beforeIns.prevLoc])

				#print '\t -> %s' %(se.getAst())#.isTainted()
				#print '\t\t'+str(se.isSymbolized())+" "+str(getCurrentRegisterValue(REG.ZF))
			#zfExpr=getFullAstFromId(getSymbolicRegisterId(REG.ZF))
			#expr=assert_(equal(bvtrue(),zfExpr))
			#print getModel(expr)
		#		print
		# beforeIns.prevLoc=currLoc>>1
	#if instruction.isBranch:
	#	print '%#x:%s' %(instruction.adress,instruction.assembly)

if __name__=='__main__':
	setArchitecture(ARCH.X86_64)
	startAnalysisFromSymbol('main')
	insertCall(afterIns,INSERT_POINT.AFTER)
	insertCall(taint,INSERT_POINT.BEFORE_SYMPROC)
	afterIns.prevLoc=0
	afterIns.bitmap=dict()
	runProgram()
	#print str(beforeIns.bitmap)
