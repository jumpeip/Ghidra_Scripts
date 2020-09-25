#This script highlights all JMP and CALL instructions in different colors
#@author Patrick Jones @jumpeip
#@category Instructions


from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import Memory
from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.mem import MemoryBlockSourceInfo
from ghidra.util.exception import CancelledException
from java.awt import Color
 
 
CALL_COLOR = Color(0, 234, 255) # Light Blue
CONDITIONAL_JUMP_COLOR = Color (220,151,52) # Light Brownish
 
#get all memory ranges
address_ranges = currentProgram.getMemory().getAddressRanges()
 
for range in address_ranges:
    instruction = currentProgram.getListing().getInstructions(range.getMinAddress(),True)
    for mnenomic in instruction:
       flow = mnenomic.getFlowType()
       if flow.isCall():
           setBackgroundColor(mnenomic.getAddress(),CALL_COLOR)
       elif flow.isConditional():
           setBackgroundColor(mnenomic.getAddress(), CONDITIONAL_JUMP_COLOR)