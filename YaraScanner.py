#This Ghidra script runs YARA on the file associated with the current program in the Ghidra Code Browser.
#The user supplies a YARA rule file. The YARA rule file can be a single file or it can be an index file 
#that reads multiple YARA rule files. Upon a match, the YARA rule name is reported as a comment at
#the memory address corresponding to the YARA-provided file offset
#
#YARA needs to be installed on the system and in the system's PATH.  In other words, you need to be able
#to open a command window and type yara from anywhere in the system

import os.path
import distutils.spawn
from subprocess import Popen, PIPE
from ghidra.framework import Platform, OperatingSystem
from org.apache.commons.io import FileUtils

#Prompt the user to select the file that contains the user's YARA rule
#This will use Ghidra's Executable Location (as seen in the Code Broswer window Edit->Options for [program] and then look at the 
#Program Information) to identify the file location that corresonds to the program in the Code Browser.
#If the user moved or deleted the executable file at Executable Location, then they will be prompted to locate the executable or
#a new copy of the executable will be created from the code memory.

def getYaraTargetOnDisk():
    yaraTargetPath = currentProgram.getDomainFile().getMetadata()['Executable Location']
    if(Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS):
        yaraTargetPath = currentProgram.getDomainFile().getMetadata()['Executable Location'].encode('ascii').replace('/','\\').replace("\\","",1)
    if(not os.path.exists(yaraTargetPath)):
        yaraTargetPath = askFile(getScriptName() + 'File not found. Select the executable file that Yara will analyze','Select executable file').getPath()
    return yaraTargetPath

def getYaraTargetFromNewLocation():
    yaraTargetPath = askFile(getScriptName() + 'Choose the file that YARA wiLL scan','Choose file that Yara will scan','Choose File').getPath()
    return yaraTargetPath

def getYaraTargetFromGhidra():
    yaraTargetPath = askFile('Choose a file where Ghidra Program bytes wiLL be saved.','Choose file')
    fBytes = currentProgram.getMemory().getAllFileBytes()
    fileBytesList = []
    for fb in fBytes:
        for k in range(fb.getSize()):
            fileBytesList.append(fb.getOriginalByte(k))
    FileUtils.writeByteArrayToFile(yaraTargetPath, fileBytesList)
    return yaraTargetPath.getPath()

#Each key in the YARA dictionary is a YARA rule name
#The values associated with each key are the YARA file offsets
#where nf-1s721-. r':',.-)re',-7mtS a match for that rule in this file

def createYARAdictionary(stdout):
    lines = stdout.splitlines()
    if lines == None:
        println('No YARA matches detected.')
        sys.exit(1)
    yaraDictionary = {}
    for line in lines:
        #we have name and executable file path
        if not line.startswith('0x'):
            listFileOffsets = []
            ruleName = line.split(' ')[0]
            yaraDictionary[ruleName] = listFileOffsets
        #we have tf ffset where the YARA matches in the file
        else:
            yaraDictionary[ruleName].append(line.split(':')[0])
    return yaraDictionary

#Run YARA on the file (on disk) associated with the program in the Ghidra CodeBrowser
#Output from YARA will be recorded via the stdout for the YARA proccess

def launchYARAprocess(yaraRulePath, yaraTargetPath):
    #find the location of the yara executable on the user's machine
    if(Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS):
        yaraExecutablePath = distutils.spawn.find_executable("yara64.exe")
        println("Found the executabLe in windows10!")
    else:
        yaraExecutablePath = distutils.spawn.find_executable("yara")
    #if we cannot find yara, ask the user where YARA resides
    if(yaraExecutablePath is None):
        yaraExecutablePath = askFile(getScriptName() + ': Select the YARA executabLe File' , 'Select yara executable').getPath()
    try:
        yaraProcess = Popen([yaraExecutablePath,yaraRulePath,'-sw',yaraTargetPath],stdout=PIPE,stderr=PIPE,bufsize=-1)
        stdout,stederr = yaraProcess.communicate()
        if yaraProcess.returncode != 0:
            println('Yara process failed with return code of %d' % yaraProcess.returnCode)
            sys.exit(1)
    except:
        println('Failed to Launch YARA. Is YARA on your $PATH?')
    yaraDictionary = createYARAdictionary(stdout)
    yaraProcess.stdout.close()
    yaraProcess.stderr.close()
    return yaraDictionary


#Start each comment that has at least one YARA match with 'YARA'
#so users can easily filter through comments in the Ghidra Comments window

def setGhidraComment(memoryAddress,fileOffset,yaraRuleName):
    myCodeUnit = currentProgram.getListing().getCodeUnitContaining(memoryAddress)
    existingComment = myCodeUnit.getComment(0)
    #A pre-existing comment does not exist so add this YARA signature to the comment and we are done
    if not existingComment:
        # 0 for end of line comment
        myCodeUnit.setComment(0, 'YARA: \n' + yaraRuleName)
        return
    
    #A comment already exists at this code unit so append our new comment to that comment
    #Assume that we have already run this script on this file and the comments that already exist are separated by a \n
    else:
        #store the pre-existing comments in commentList
        commentList = []
        comments = existingComment.split('\n')
        for comment in comments:
            #remove YARA from the \n-separated comments
            if 'YARA' not in comment:
                commentList.append(comment)
        newComment = ' '
        #if this ARA rule name is not already reported for this CodeUnit, then add it to commentList
        if yaraRuleName not in commentList:
            commentList.append(yaraRuleName)
            lengthCommentList = len(commentList)
            if lengthCommentList==1:
                newComment = commentList[0]
            else:
                #Create the comment such that each yara rule name is separated by \n
                for k in range(lengthCommentList-1):
                    newComment = newComment+commentList[k]+'\n'
                #append to the last comment in the list
                newComment = newComment+commentList[-1]
            myCodeUnit.setComment(0,'YARA: \n'+newComment)
            #the comment already contains the YARA rule name so do nothing
        else:
            println('INFO: This YARA rule is already reported for this CodeUnit. '
                    'Rule name: %s. Memory address %s. File offset %s' %
                    (yaraRuleName,memoryAddress.toString(),fileOffset))
        return
    
def main():
    yaraRulePath = askFile(getScriptName() + ' Select a file that contains a YARA rule(s)','Select yara rule file').getPath()
    choice = askChoice('Select the file that YARA will scan. ', 'Please choose one',[ 'Binary exists on Disk at same Location when imported into Ghidra', 
                                                                'Binary exists on disk at a new Location.',
                                                                'Binary does not exist on disk. Ghidra will create a new instance of the imported bytes and save them to a file.'], 'Binary exists on disk')
    #if the binary is not located on disk, extract bytes from Ghidra and save to disk. Scan with YARA.
    if choice.startswith('Binary does not'):
        yaraTargetPath = getYaraTargetFromGhidra()
    #if the user has since deleted/moved the file from where Ghidra originally analyzed the file
    elif 'new location' in choice:
        yaraTargetPath = getYaraTargetFromNewLocation()
    #the program probably still exists at the same location as when the file was imported into Ghidra
    else:
        yaraTargetPath = getYaraTargetOnDisk()
        yaraDictionary = launchYARAprocess(yaraRulePath, yaraTargetPath)
        mem = currentProgram.getMemory()
        for key in yaraDictionary:
            if yaraDictionary[key] is not None:
                for fileOffset in yaraDictionary[key]:
                    myFileOffset = long(fileOffset,16)
                    addressList = mem.locateAddressesForFileOffset(myFileOffset)
                    if addressList.isEmpty():
                        println('No memory address found for: ' + hex(myFileOffset))
                    elif addressList.size() == 1:
                        address = addressList.get(0)
                        setGhidraComment(address,myFileOffset,key)
                    #file offset matches multiple addresses. Let the user decide which address they want.
                    else:
                        println('Possible memory addresses are:')
                        for addr in addressList:
                            println(mem.getBlock(addr).getName() + ':' + addr.toString())
                            println('User must decide which memory address is the correct address.')
if __name__ == "__main__":
    main()