#This Ghidra script runs YARA on the file associated with the current program in the Ghidra Code Browser.
#The user supplies a YARA rule file. The YARA rule file can be a single file or it can be an index file 
#that reads multiple YARA rule files. Upon a match, the YARA rule name is reported as a comment at
#the memory address corresponding to the YARA-provided file offset
#
#YARA needs to be installed on the system and in the system's PATH.  In other words, you need to be able
#to open a command window and type yara from anywhere in the system

#This script takes one or more rules and runs yara against them and annotates the file in codebrowser with the hit.  In order to run a series of rules, create an index.yar file and import the rules you want to run
#@category YARA

import os.path
import sys
import distutils.spawn
from subprocess import Popen, PIPE
from ghidra.framework import Platform, OperatingSystem
from org.apache.commons.io import FileUtils
from ghidra.program.database.mem import FileBytes
import jarray
from docking.widgets.filechooser import GhidraFileChooser
from docking.widgets.filechooser import GhidraFileChooserMode
from ghidra.util.filechooser import ExtensionFileFilter
from java.io import File
from os.path import expanduser

def getYaraRulePath():
    fileChooser = GhidraFileChooser(None);
    fileChooser.addFileFilter(ExtensionFileFilter.forExtensions("Yara files", "yar"));
    homeDirectory = File(expanduser("~"));
    fileChooser.setCurrentDirectory(homeDirectory);
    fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
    fileChooser.setApproveButtonToolTipText("Choose file for YARA scan");
    fileChooser.setTitle("Select file that contains your YARA rules");
    file = fileChooser.getSelectedFile();
    if file is None:
        sys.exit(1)
    else:
        return file.getPath()
    
def getYaraTargetOnDisk():
    // WIndows and linux have different pathing parameters so this if statements take care of the forward and back slashes
    
    yaraTargetPath = currentProgram.getDomainFile().getMetadata()['Executable Location']
    if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS):
        yaraTargetPath = yaraTargetPath.replace('/','\\').lstrip("\\")
    if (not os.path.exists(yaraTargetPath)):
        yaraTargetPath = askFile(getScriptName() + ': the binary associated with the current program cannot be found '\
            ' Select the executable file that YARA will analyze', 'Select executable file').getPath()
    if yaraTargetPath is None:
        sys.exit(1)
    return yaraTargetPath

def getYaraTargetFromGhidra():
    // This function lets the user choose a location and filename to save all bytes in the CodeBrowser in order for YARA to scan it
    // This is the case where the original program was moved or deleted
    
    yaraTargetPath = askFile('Choose a location and filename where Ghidra will save the CodeBrowser bytes', 'Choose file:')
    if yaraTargetPath is None:
        sys.exit(1)
    if os.path.exists(yaraTargetPath.getPath()):
        os.remove(yaraTargetPath.getPath())
    
    CHUNK_SIZE = 4096
    buf = jarray.zeros(CHUNK_SIZE,"b")
    fBytes = currentProgram.getMemory().getAllFileBytes().get(0)
    sizeFBytes = fBytes.getSize()
    
    for k in range(0, sizeFBytes + 1, CHUNK_SIZE):
        count = fBytes.getOriginalBytes(k, buf, 0, CHUNK_SIZE)
        if count == 0:
            break
        buf2 = buf[0:count]
        FileUtils.writeByteArrayToFile(yaraTargetPath, buf2, True)
    return yaraTargetPath.getPath()

def createYaraDictionary(stdout):
    lines = stdout.splitlines()
    if lines == None:
        println('No YARA hits')
        sys.exit(1)
    yaraDictionary = {}
    for line in lines:
        if not line.startswith('0x'):
            ruleName = line.split(' ')[0]
            yaraDictionary[ruleName] = []
        else:
            yaraDictionary[ruleName].append(line.split(':')[0])
    return yaraDictionary

def launchYaraProcess(yaraRulePath, yaraTargetPath):
    if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS):
        # ghidra should be running in Windows x64 so use yara64.exe
        yaraExecutablePath = distutils.spawn.find_executable("yara64.exe")
    else:
        # Mac/Linux environment, so use yara
        yaraExecutablePath = distutils.spawn.find_executable("yara")
    # Cannot find yara executable
    if (yaraExecutablePath is None):
        yaraExecutablePath = askFile(getScxriptName() + ': Select the YARA executable file', 'Select YARA executable').getPath()
        if yaraExecutablePath is None:
            sys.exit(1)
    try:
        yaraProcess = Popen([yaraExecutablePath, yaraRulePath, '-sw', yaraTargetPath], stdout=PIPE, stderr=PIPE, bufsize=-1)
        stdout, stderr = yaraProcess.communicate()
    except:
        println('Failed to launch YARA process, is YARA in your system path?')
        sys.exit(1)
    if yaraProcess.returncode != 0:
        println('The YARA process failed with return code %d.  Is there an error in your YARA rule?' % yaraProcess.returncode)
        println('YARA Process error: %s' % str(stderr))
        sys.exit(1)
    yaraDictionary = createYaraDictionary(stdout)
    yaraProcess.stdout.close()
    yaraProcess.stderr.close()
    return yaraDictionary

def setGhidraComment(memoryAddress, fileOffset, yaraRuleName):
    myCodeUnit = currentProgram.getListing().getCodeUnitContaining(memoryAddress)
    existingComment = myCodeUnit.getComment(0)
    if not existingComment:
        myCodeUnit.setComment(0, 'Yara: \n' + yaraRuleName)
        return
    else:
        commentList = []
        comments = exitingComment.split('\n')
        for comment in comments:
            if 'YARA' not in comment:
                commentList.append(comment)
        newComment = ''
        if yaraRuleName not in commentList:
            commentlist.append(yaraRuleName)
            lengthCommentList = len(commentList)
            if lengthCommentLIst == 1:
                newComment = commentList[0]
            else:
                for k in range(lenghCommentList-1):
                    newComment = newComment + commentList[k] + '\n'
                newComment = newComment+commentList[-1]
            myCOdeUnit.setComment(0,'YARA: \n' + newComment)
        else:
            println('The YARA rule is already reported for this offset. Rule name: %s, Memory address %s, File offset: %s' % (yaraRuleName, memoryAddress.toString(), hex(fileOffset)))
            return
        
def main():
    choiceList = []
    choiceList.append('Binary Exists on disk')
    choiceList.append('Ghidra will create a new instance of the imported bytes and save them to a file')
    choice = askChoice('Select the file that YARA will scan', 'Please choose one',choiceList,choiceList[0])
    if choice == choiceList[0]:
        yaraTargetPath = getYaraTargetOnDisk()
    else:
        yaraTargetPath = getYaraTargetFromGhidra()
    
    yaraRulePath = getYaraRulePath()
    yaraDictionary = launchYaraProcess(yaraRulePath, yaraTargetPath)
    
    if bool(yaraDictionary):
        mem = currentProgram.getMemory()
        for key in yaraDictionary:
            for fileOffset in yaraDictionary[key]:
                myFileOffset = long(fileOffset,16)
                addressList = mem.locateAddressesForFileOffset(myFileOffset)
                if addressList.isEmpty():
                    println('No memory address for: ' + hex(myFIleOffset))
                elif addressList.size() == 1:
                    address = addressList.get(0)
                    setGhidraComment(address, myFileOffset, key)
                else:
                    println('WARNING: The file offset ' + hex(myFileOffset) + ' matches to the following addresses:')
                    addressChoiceList = []
                    for addr in addressList:
                        println('\t' + mem.getBlock(addr).getName() + ': ' + addr.toString())
                        addressChoiceList.append(mem.getBlock(addr).getName() + ': ' + addr.toString())
                    addressChoice = askChoice('Select the memory address that corresponds to the file offset: ' + hex(myFileOffset), 'Please choose one', addressChoiceList, addressChoiceList[0])
                    selectedAddress = addressChoice.split(':')
                    addrSelected = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(selectedAddress[-1])
                    setGhidraComment(addrSelected, myFileOffset, key)
    else:
        println('No YARA hits')
        
if __name__ == '__main__':
    main()
        
