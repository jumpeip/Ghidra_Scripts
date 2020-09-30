//This script looks for unique XOR values.  I search for occurrances of XOR and then look at the operands.  If they match, then disregard them.  I am more looking for somethig like XOR EAX, 0x5c
//@author Patrick Jones @jumpeip
//@category Instructions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;


public class Find_Unique_XOR_Values extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Instruction instruction = getFirstInstruction();
		Address inst_addr = instruction.getMinAddress();
		String[] regArray = new String[] {"EAX","EBX","ECX","EDX","ESI","EBP","EDX","EDI","AX","BX","CX","DX","SI","AL","AH","BL","BH","CL","CH","DL"};
		String[] wordArray = new String[] {"byte","dword","word","qword"};
		
		while (true) {
			if (monitor.isCancelled()) {
				break;
			}
			
			if (instruction == null) {
				break;
			}
			
			inst_addr = instruction.getMinAddress();
			if (instruction.getMnemonicString().contains("XOR")) {
				String operand1 = instruction.getDefaultOperandRepresentation(0);
				String operand2 = instruction.getDefaultOperandRepresentation(1);
				if (!(operand1.equals(operand2))) {
					 boolean itsReg = checkRegArg(regArray,operand2);
					 boolean itsdWord = checkdWord(wordArray,operand2);
					 
					 if (!itsReg) {
						 if (!itsdWord ) {
							 printf("XOR Operation -> %s %s\n",inst_addr,instruction);
							 bookMarkXOR(inst_addr, instruction);
						 } // end if
					 } // end if
				} // end if
			}// end if
			instruction = getInstructionAfter(instruction);
		} // end while
	} // end run function


	public static boolean checkRegArg(String[] regarr, String target) {
		for (String s: regarr) {
			if (s.equals(target))
				return true;
		}
		return false;
	} // and checkRegArg
	
	public static boolean checkdWord(String[] wordarr, String target) {
		for (String s: wordarr) {
			if (s.contains(target))
				return true;
		}
		return false;
	} // end checkdWord
	
	private void bookMarkXOR(Address instr, Instruction instruction) {
		currentProgram.getBookmarkManager().setBookmark(instr, BookmarkType.ANALYSIS,"NON-ZERO XOR","NON-ZERO XOR: " + instruction);
	} // end bookMarkXOR
} // end class