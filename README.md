# Simple_fuzzer
Fuzzer for config file 

Implemented a program that performs file format fuzzing.
The implemented program carries out the following actions:
- Change the original file (one-byte replacement, replacement of several bytes, adding to the file);
- replace bytes to boundary values (0x00, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFFFF / 2, 0xFFFF / 2 + 1, 0xFFFF / 2-1, etc.);
- to have an automatic mode of operation, in which successive replacement of bytes in a file is made;
- find in the file characters that separate the fields (",: =;");
- Expand the values of the fields in the file (append to the end, increase the length of the lines in the file);
- find the boundaries of fields in the file based on the analysis of several configuration files;
- launch the program under investigation;
- to detect the appearance of an error in the application under study;
- receive error code and stack states, registers and other information at the time the error occurred;
- log the file information about the errors that occurred and the corresponding input parameters (the replacements made).

An IDC / IDAPython script has been developed that does the following:
- search in the program functions for data entry (fread, fscanf, read, fgets, ...);
- search for unsafe function calls (strcpy, sprintf, strncpy, memcpy, memmove, ...);
- Determine the sequence of calls (execution paths) from the data entry functions to the call of unsafe functions.
The developed IDC / IDAPython script displays the following information:
- the name of the found function;
- the address from which this function is called.
