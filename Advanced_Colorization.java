//Sets up colorization of instructions.  Also clears colors from instructions in the case of exporting the file from ghidra to share as to not interfere with someone else's analysis
//@author Patrick Jones
//@category Instructions
//@keybinding
//@menupath
//@toolbar

import java.awt.Color;
import java.util.Arrays;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class Advanced_Colorization extends GhidraScript {
       // Global strings for this class
       final public String CALL = "CALL";
       final public String LEA = "LEA";
       final public String XOR = "XOR";
       String[] mathArray = new String[] { "SAR", "SAL", "SHR", "SHL", "ROR", "ROL", "IDIV", "DIV", "IMUL", "MUL", "NOT"};
       String[] jumpArray = new String[] { "JMP", "JE", "JZ", "JNE", "JNZ", "JG", "JNLE", "JGE", "JNL", "JL", "JNGE", "JLE", "JNG", "JA",
    		   "JNBE", "JAE", "JNB", "JB", "JNAE", "JBE", "JNA", "JXCZ", "JC", "JNC", "JO", "JNO", "JP", "JPE", "JNP", "JPO", "JS", "JNS" };

       // define color shades
       Color XORCOLOR = new Color(245, 205, 255); // light purple
       Color MATHCOLOR = new Color(200, 240, 255); // blue
       Color JUMPS = new Color(255, 255, 224); // light yellow
       Color CALLS = new Color(255, 220, 220); // light red
       Color LEACOLOR = Color.LIGHT_GRAY; // duh, light gray

       @Override
       public void run() throws Exception {
              ColorizingService service = state.getTool().getService(ColorizingService.class);
              if (service == null) {
                     println("Can't find ColorizingService service");
                     return;
              }

              String choice = askChoice("Colorizer", "Please select one",
                           Arrays.asList(new String[] { "Set Colors", "Jumps and Calls", "XOR Calls", "Math Funcs", "Clear Colors"}), "Set Colors");

              switch(choice) {
	              case "Set Colors":
		              set_all_colors();
		              break;

	       		  case "Jumps and Calls":
	            	  highlight_jumps_and_calls();
	            	  break;

	       		  case "XOR Calls":
	            	  highlight_xor_calls();
	            	  break;

	       		  case "Math Funcs":
	            	  highlight_math_instructions();
	            	  break;

	       		  case "Clear Colors":
	                     clear_colors();
	                     break;

	              default:
	                	break;
              } // switch
       } // end public void run

       public void highlight_jumps_and_calls() {
    	   Instruction instruction = getFirstInstruction();
           while (true) {
                 if (instruction == null) {
                        break;
                 }
                 if (instruction.getMnemonicString().equals(CALL)){
                        Address address = instruction.getAddress();
                        setBackgroundColor(address, new Color(255, 220, 220)); // light red
                 }
                 for (String s: jumpArray) {
          			if (s.equals(instruction.getMnemonicString())) {
          				Address address = instruction.getAddress();
          				setBackgroundColor(address, JUMPS);
          			}
                  }
                 instruction = getInstructionAfter(instruction);
           } // while
       } // end highlight_jumps_and_Calls

       public void highlight_xor_calls() {
    	   Instruction instruction = getFirstInstruction();
           while (true) {
                 if (instruction == null) {
                        break;
                 }
                 if (instruction.getMnemonicString().equals(XOR) && (!instruction.getDefaultOperandRepresentation(0).equals(instruction.getDefaultOperandRepresentation(1)))) {
                     Address address = instruction.getAddress();
                     setBackgroundColor(address, XORCOLOR);
                 }

                 instruction = getInstructionAfter(instruction);
           } // while
       } // end highlight_xor_Calls

       public void highlight_math_instructions() {
    	   Instruction instruction = getFirstInstruction();
           while (true) {
                 if (instruction == null) {
                        break;
                 }
                 for (String s: mathArray) {
         			if (s.equals(instruction.getMnemonicString())) {
         				Address address = instruction.getAddress();
         				setBackgroundColor(address, MATHCOLOR);
         			}
                 }
                 instruction = getInstructionAfter(instruction);
           }
       } // end highlight_math_instructions


       public void set_all_colors() {
    	   Instruction instruction = getFirstInstruction();
           while (true) {
                 if (instruction == null) {
                        break;
                 }
                 if (instruction.getMnemonicString().equals(CALL)){
                        Address address = instruction.getAddress();
                        setBackgroundColor(address, CALLS); // light red
                 }
                 for (String s: jumpArray) {
           			if (s.equals(instruction.getMnemonicString())) {
           				Address address = instruction.getAddress();
           				setBackgroundColor(address, JUMPS); // light yellow
           			}
                 }
                 for (String m: mathArray) {
          			if (m.equals(instruction.getMnemonicString())) {
          				Address address = instruction.getAddress();
          				setBackgroundColor(address, MATHCOLOR);
          			}
                  }
                 if (instruction.getMnemonicString().equals(LEA)){
                        Address address = instruction.getAddress();
                        setBackgroundColor(address, LEACOLOR);
                 }
                 // Looking for XOR operations where it is not a zeroing effect such as XOR EAX,EAX
                 if (instruction.getMnemonicString().equals(XOR) && (!instruction.getDefaultOperandRepresentation(0).equals(instruction.getDefaultOperandRepresentation(1)))) {
                        Address address = instruction.getAddress();
                        setBackgroundColor(address, XORCOLOR);
                 }

                 // iterate the next instruction or you WILL get in an infinite loop :)
                 instruction = getInstructionAfter(instruction);
           } // end while
       }

       public void clear_colors() {
              Instruction instruction = getFirstInstruction();
              while (true) {
                     if (instruction == null) {
                           break;
                     }
                     Address address = instruction.getAddress();
                     clearBackgroundColor(address);
                     instruction = getInstructionAfter(instruction);
              }
       } // end clear_colors
} // end class
