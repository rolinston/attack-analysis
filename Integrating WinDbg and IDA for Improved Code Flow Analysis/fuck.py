# Windbg log parser IDApython script
# Author: Matthew Graeber
# Modify: ipfans

# Update:
# v0.1:
#   Initialized. (Matthew Graeber)
#
# v0.2: 
#   1) fix indent;
#   2) fix bugs to identify the unsymbol program;
#   3) some others' fix.

# I highly recommend your WinDbg log contain the output from 'lmp'
# Otherwise, if the module base in WinDbg and IDA don't match,
# this will not markup IDA properly.


from idaapi import *

fh = open(AskFile(1, "*.log", "Select Windbg log file"), 'r')

colors = {'red':0x0000FF, 'green':0x00FF00, 'blue':0xFF0000, 'pink':0xFF99FF, 'black':0x00000000, 'white':0xFFFFFFFF}
color = AskStr("red, green, blue, pink(default), black, white", "Enter the color you want to use")

if color in colors.keys():
    color_val = colors[color]
else: # default to white background
    color_val = colors['pink']

line = fh.readline()
modules_listed = False

ins_addr = [] # will contain list of addresses and comment
base_addresses = {} # dictionary of all loaded modules and their base addresses
registers = {} # register values during trace

while line:
    if '***' in line[0:3]: #skip errors
        line = fh.readline()

    if 'start' in line: # beginning of module base listing
        modules_listed = True
        while True:
            line = fh.readline() # read first module listing
            if '<none>' in line:
                tokens = line.strip().split()
                base_addresses[tokens[2]] = tokens[0] # save in the following form: {'kernel32':'760f0000'}
                #print base_addresses
            else: # end of module listing
                break

    if 'eax=' in line[0:4]: # get first line of register values
        tokens = line.strip().split()
        for i in tokens:
            tokens2 = i.split('=')
            registers[tokens2[0]] = tokens2[1]
            #print registers

    if 'eip=' in line[0:4]: # get EBP and ESP from the next line
        tokens = line.strip().split()
        for i in tokens:
            tokens2 = i.split('=')
            if tokens2[0] == 'esp':
                 registers[tokens2[0]] = tokens2[1]
            if tokens2[0] == 'ebp':
                 registers[tokens2[0]] = tokens2[1]

    if 'cs=' in line[0:3]: # extract module name
        module = fh.readline()
        if '!' in line:
            module = module.split('!')[0] # have symbols
        else:
            module = module.split('+')[0] # no symbols
            module = module.split('!')[0] # fix some moduule have symbols

        # extract addr, opcode, instruction
        line =fh.readline()
        tokens = line.strip().split()
        #print tokens
        if tokens[1] != 'cc': # skip debug breakpoints
            if modules_listed: # Calculate offsets from module base
                if tokens[0] != '***':
                    try:
                        base = long(base_addresses[module], 16)
                        temp = [long(tokens[0], 16) - base]
                        #print temp
                    except:
                        print base_addresses[module]
                        print tokens[0]
            else: # use absolute virtual addresses
                temp = [long(tokens[0], 16)] # convert hex string to IDA ea form

            for i in registers.keys(): # Make comments for referenced registers
                if i in line:
                    temp.append(i + "=" + registers[i])

                    temp2 = tokens[len(tokens)-1] # get last item in line
                    if ':' in temp2: # check for pointer dereference
                        temp2 = temp2.split(':')
                        temp.append("Ptr deref: " + temp2[len(temp2)-1]) # append opcode pointer for IDA comment

            ins_addr.append(temp)

    line = fh.readline()

for i in ins_addr:
    if modules_listed:
        ea = i[0] + get_imagebase()
    else:
        ea = i[0]

    if ea == BADADDR:
        print("BAD ADDRESS @ 0x%08x" % ea)
        continue

    SetColor(ea, idc.CIC_ITEM, color_val)

    if len(i) > 1:
        commentStr = ""
        for j in range(1, len(i)):
            commentStr += i[j]
            if j != len(i) - 1:
                commentStr += "\n"
        if Comment(ea):
            MakeComm(ea, Comment(ea) + "\n" + commentStr) # Prevents overwriting existing comments
        else:
            MakeComm(ea, commentStr)

fh.close()
