#Highlight CALL and JMP calls in code
#@author Patrick Jones twitter:lord_nikon
#@category Instructions

# Included the following as common includes for future additions
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import Memory
from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.mem import MemoryBlockSourceInfo
from ghidra.util.exception import CancelledException
from java.awt import Color

service = state.getTool().getService(ColorizingService)
listing = currentProgram.getListing()
inst_list = listing.getInstructions(1)
while inst_list.hasNext():
    ins = inst_list.next()
    addr = ins.getAddress()
    mnenomic = ins.getMnemonicString()
    if (mnenomic == "CALL") or (mnenomic == "JMP"):
        try:
            service.setBackgroundColor(addr,addr,Color(255,200,200))
        except:
            pass