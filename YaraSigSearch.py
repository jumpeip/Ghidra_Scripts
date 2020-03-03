#Run YARA against current file.  
#
# Thr trick to Ghidra getting the offsets correctly from Yara results is to import as a RAW file, run the script
# and then auto-analyze the file.  If you load the file directly, Ghidra will not load the entire file but rather
# read the sections and only load those memory regions so if you have a Yara hit outside those regions, the 
# script will complain and it won't mark the hit properly.  This could be automated by using ghidra headless
# and importing as RAW, run this as a pre-script but you would need to hard set a yara file since headless 
# does not allow GUI based scripts, then auto-analyze as a post-script
#Todo: Add multiple yara files
#@author Patrick Jones (jumpeip)
#@category Search
#@keybinding
#@menupath
#@toolbar

# python imports
import sys, os
from subprocess import Popen, PIPE

# Ghidra Imports
from subprocess import Popen, PIPE
from ghidra.program.model.listing import CodeUnit
from ghidra.program.util import ProgramSelection
from ghidra.util.exception import CancelledException
from ghidra.program.model.mem import MemoryAccessException
from ghidra.feature.vt.api.correlator import address

# Constants
BUFFER_SIZE = 10*1024*1024
SCRIPT_NAME = "YaraSigSearch.py"
COMMENT_TYPE = CodeUnit.PRE_COMMENT

try:
    rule_file = askFile(SCRIPT_NAME, "Search file with YARA rule").getPath()
except CancelledException as e:
    print("[-] Selection Cancelled " + str(e))
    exit()

# Get Minimum and Maximum address. COnvert to get length
minAddress = currentProgram.getMinAddress()
maxAddress = currentProgram.getMaxAddress()
length = int(str(maxAddress), base=16) - int(str(minAddress), base=16)

print("Starting Address: %s" % minAddress)
print("Ending Address: %s" % maxAddress)
print("Size of File Memory: %d" % length)
print("\n[+]Searching ... ")

try:
    bytes = getBytes(minAddress, length)
except MemoryAccessException as e:
    print("[-] Failed to get bytes " + str(e))
    exit()

try:
    # Windows
    if (currentProgram.getDomainFile().getMetadata()["Executable Location"].startswith("/C")):
        file_location = (currentProgram.getDomainFile().getMetadata()["Executable Location"].encode("ascii").replace("/","\\").replace("\\","",1))
    else:
        # Linux/OSX
        file_location = currentProgram.getDomainFile().getMetadata()["Executable Location"]
    print("File Location: %s" % file_location)
except:
    print("Fuck Me, what kind of dumbass system is this?")

try:
    pYara = Popen(['yara', rule_file, "-gs", file_location], stdout=PIPE, stderr=PIPE, bufsize=BUFFER_SIZE)
    stdout, stderr = pYara.communicate()
    print("Finished running Yara against file")
except:
    print("Failed to launch yara.  Check PATH or place it in a system directory (not safe I know, but fuck it)")

if pYara.returncode != 0:
    print("[-] Failed to get returncode")
    exit()

lines = stdout.splitlines()
if lines == None:
    print("There is nothing returned from yara scan")
    exit()

rule = ""
tag = ""
print(lines)

for yaraLine in lines: 
    if yaraLine.startswith("0x"):
        ldata = yaraLine.split(":")
        addr = int(ldata[0],16)
        print("Yara offset from hit: %s" % minAddress.add(addr))
        thestring = ldata[1]
        match = ldata[2]
        print("Creating bookmark at: %s" % minAddress.add(addr))
        createBookmark(minAddress.add(addr), SCRIPT_NAME, rule + " " + match)
        cu = currentProgram.getListing().getCodeUnitAt(minAddress.add(addr))
        if cu == None:
            print("[-] Error, cannot set comment at codeUnit. Memory location %s does not exist" % minAddress.add(addr))
            continue
        comment = cu.getComment(COMMENT_TYPE)
        if comment == None or comment == "":
            comment = ""
        else:
            comment += "\n"
        comment += SCRIPT_NAME + "\n"
        comment += rule + " " + tag + "\n"
        comment += thestring + ": " + match
        cu.setComment(COMMENT_TYPE, comment)
    else:
        rule = yaraLine.split()[0]
        tag = yaraLine.split()[1]
        print(rule + " " + tag)
print("Finished scanning and setting comments and bookmarks")
