# Ghidra_Scripts
Ghidra scripts I am creating for reverse engineering while learning how to write them for Ghidra

The first script I wrote calls YARA externally to get the results.  Although I have pyYara installed,
I cannot figure out how to get Ghidra to recognize it.  I'll figure it out eventually but it may have something 
to do with jython.

Anyway, this will take a file loaded into Ghidra and scan the file with yara gatherig the results from the -s
option which will show the physical offset in the file.  This takes the physical offset and converts it to a 
virtual offset and places a comment in the file at the proper offset.  To find the hits, bring up the comments
window and then filter on YARA.

Place this script in your ghidra_scripts directory or add it to any directory you want and then add that directory
to the list of script locations.  Yara executable should be in your path.  Also, if you use a different drive other
than C:\ then just change the script that modifies the backslashes

