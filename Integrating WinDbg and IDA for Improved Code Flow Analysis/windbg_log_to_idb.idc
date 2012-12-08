#include <idc.idc>

/*
 * WinDbg logfile to IDA coloring
 *                   -cody "color blind" pierce
 *
 * This colors blocks youve hit during a windbg run.
 * For instance when auditing.
 *
 *  0:001> .logopen c:\my_debug_run.log
 *  0:001> pa 01005c15  <--- address we stop at
 *  0:001> .logclose
 *
 */

// We can define colors here be aware IDA does 0xBBGGRR

#define GREEN 0x00ff00
#define RED   0x0000ff

static color(str, colors, comms)
{
    auto strindex, eipstring, eip, color, line, m, mline, end;
    
    // DEFCOLOR is original color scheme (will reset your path)
    //color = DEFCOLOR;
    color = GREEN;

    if ( strstr(str, "Access Violation") != -1 )
    {
        color = RED;
    }
    
    if ( comms )
    {
        if ( (strindex = strstr(str, "eip=")) == -1 )
        {
            if ( strstr(str, "eax=") != -1 )
            {
                return 0;
            }
            else if ( strstr(str, "cs=") != -1 )
            {
                return 0;
            }
            else
            {
                eipstring = substr(str, 0, 8);
                eip = xtol(eipstring);
                
                if ( eip < 0x00100000 )
                {
                    return 0;
                }
                
                end = strstr(str, 0x0a);
                line = substr(str, 25, end);
                if ( strstr(line, "mov") != -1 )
                {
                    if ( strstr(line, "[") != -1 )
                    {
                        m = strstr(line, "=");
                        mline = substr(line, m+1, end);
                        //Message("[*] Setting %s @ %x\n", mline, eip);
                        MakeComm(eip, mline);
                    }
                }
                else if ( strstr(line, "j") != -1 )
                {
                    m = strstr(line, "[");
                    mline = substr(line, m+1, strstr(line, "]"));
                    //Message("[*] Setting %s @ %x\n", mline, eip);
                    MakeComm(eip, mline);
                }
                else if ( strstr(line, "cmp") != -1 )
                {
                    if ( strstr(line, "[") != -1 )
                    {
                        m = strstr(line, "=");
                        mline = substr(line, m+1, end);
                        //Message("[*] Setting %s @ %x\n", mline, eip);
                        MakeComm(eip, mline);
                    }
                }
                // Uncomment this to reset comments
                //MakeComm(eip, "");
            }
        }
    }
    
    if ( colors )
    {
        eipstring = substr(str, 4, 12);
        
        if ( eipstring == "" )
        {
            Message("[!] Problem chopping EIP\n");
            return 0;
        }
    
        eip = xtol(eipstring);
        
        //Message("[*] Setting color @ %x\n", eip);
        SetColor(eip, CIC_ITEM, color);
        
        return eip;
    }
    
    return 1;
}

static main()
{
    auto fh, filename, filestring, colors, comms;
    
    filename = AskFile(0, "*.log", "Select Windbg logfile to parse");
    fh = fopen(filename, "r");
    
    if ( fh >= 0 )
    {
        colors = AskYN(1, "Add line colors?");
        if (colors == -1)
        {
            colors = 0;
        }
        
        comms = AskYN(0, "Add line comments?");
        if (comms == -1)
        {
            comms = 0;
        }
            
        while ((filestring = readstr(fh)) != -1)
        {
            color(filestring, colors, comms); 
        }
        
        fclose(fh);
    } else {
        Message("[!] Couldn't open file\n");
    }
}