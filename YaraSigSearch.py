#Search current file with yara signatures
#@author Patrick Jones @jumpeip
#@category Search:YARA


import sys
sys.path.insert(0,"/Library/Python/2.7/site-packages/") # Location of site packages in your python (this is OSX)
import os, requests
from subprocess import Popen, PIPE

# Ghidra Imports
from subprocess import Popen, PIPE
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Listing
from ghidra.program.util import ProgramSelection
from ghidra.util.exception import CancelledException
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.mem import Memory
from ghidra.program.model.mem import MemoryBlockSourceInfo
from ghidra.feature.vt.api.correlator import address
from ghidra.program.model.address import Address
from __builtin__ import None

# Constants
BUFFER_SIZE = 10*1024*1024
SCRIPT_NAME = "YaraSigSearch.py"
COMMENT_TYPE = CodeUnit.PRE_COMMENT

def findGhidraVirtualOffset(fileOffset, key):
    try:
        yaraFileOffset = long(fileOffset, 16)
        mem = currentProgram.getMemory()
        memBlocks = mem.getBlocks()
        for block in memBlocks:
            sourceInfoList = block.getSourceInfos()
            sectionFileOffset = sourceInfoList.get(0).getFileBytesOffset()
            sizeSection = block.getSize()
            maxOffsetSection = sectionFileOffset + sizeSection
            if (yaraFileOffset >= sectionFileOffset) and (yaraFileOffset <= maxOffsetSection) and (sectionFileOffset != 1):
                difference = yaraFileOffset - sectionFileOffset
                virtualAddressYara = block.getStart().add(difference)
                return virtualAddressYara
        return None
    except ValueError:
        print("The following offset is not valid %s" % fileOffset)

# Check the current comments and set the YARA comment if it does not exist. If it does exist already (duplicate)
# then skip it and move on
def setGhidraComment(virtualAddress, fileOffset, ruleName):
    myCodeUnit = currentProgram.getListing().getCodeUnitContaining(virtualAddress)
    existingComment = myCodeUnit.getComment(0)
    if not existingComment:
        myCodeUnit.setComment(0,"YARA: "+ruleName)
        return
    else:
        commentList = []
        comments = existingComment.split("\n")
        for comment in comments:
            if "YARA" not in comments:
                commentList.append(comment)
        newComment = ""
        if ruleName not in commentList:
            commentList.append(ruleName)
            lengthCommentList = len(commentList)
            if lengthCommentList == 1:
                newComment = commentList[0]
            else:
                for k in range(lengthCommentList-1):
                    newComment = newComment+commentList[k] + '\n'
                newComment = newComment+commentList[-1]
            myCodeUnit.setComment(0,"YARA: "+newComment)
        else:
            print("The Yara rule %s has already been reported at %s" % (ruleName, virtualAddress.tostring(),fileOffset))
            return

def runYaraLocally():
    try:
        rule_file = askFile(SCRIPT_NAME, "Search file with YARA rule").getPath()
    except:
        exit()
    try:
        if (currentProgram.getDomainFile().getMetadata()["Executable Location"].encode("ascii").startswith("/C")): #Windows
            file_location = (currentProgram.getDomainFile().getMetadata()["Executable Location"].encode("ascii").replace("/","\\").replace("\\","",1))
            #The above changes the direction of the slashes from forward slash to back slash because of Windows.  Ghidra stores
            #The filename in a Linux naming convention and when trying to access it, Windows cannot find the file
        else: #Linux/OSX
            file_location = currentProgram.getDomainFile().getMetadata()["Executable Location"]
        print("[+] File location of YARA rule: %s" % file_location)
    except: # Not Windows or Linux/OSX
        print("Unknown file system location")
        exit()
    pYara = None
    try:
        # Place yara location in your path or in a current konwn path.  For X64 Windows, rename yara64.exe to yara.exe
        pYara = Popen(['yara', rule_file, "-gs",file_location], stdout=PIPE, stderr=PIPE, bufsize=BUFFER_SIZE)
        stdout, stderr = pYara.communicate()
        print("[+] Yara scan complete")
        if pYara.returncode != 0:
            print("[-] Failed to get return code")
            exit()
        lines = stdout.splitlines()
        if lines == None:
            print("[-] Yara did not produce any results")
        yaraDictionary = {}
        for line in lines:
            if not line.startswith("0x"):
                listOffsets = []
                ruleName = line.split(" ")[0]
                yaraDictionary[ruleName] = listOffsets
            else:
                yaraDictionary[ruleName].append(line.split(":")[0])
        return yaraDictionary
    except:
        print("[-] Failed to launch YARA.  Check PATH environment")
        exit()

yaraDictionary = runYaraLocally()
if not yaraDictionary:
    print("[-] There are no YARA hits associated with this file")
    exit()
else:
    for key in yaraDictionary:
        if yaraDictionary[key] is not None:
            for fileOffset in yaraDictionary[key]:
                yaraVirtualAddress = findGhidraVirtualOffset(fileOffset, key)
                if yaraVirtualAddress is None:
                    print("[-] Can not find the virtual address reported by Yara.  The location may be outside the loaded file (beyond end of file")
                else:
                    setGhidraComment(yaraVirtualAddress, fileOffset, key)
        else:
            print("[-] Nothing will be reported from the Yara hit.  This may be a Yara rule with no strings but just a condition")
