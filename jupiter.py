#!/Library/Frameworks/Python.framework/Versions/2.7/bin/python
#
#   TITLE   :   Jupiter - Binary Analysis Tool.
#   AUTHOR  :   Andrew Blyth (andrew.blyth@southwales.ac.uk)
#   DATE    :   March 2018
#
#
# Import the required modules for the Jupiter - Binary Analysis Tool.
from capstone import *
from elffile  import *
import sys
import os
import pefile
#
#
#
__FALSE__ = 0
__TRUE__  = 1
#
#
#
__version__     = 1.0
__title__       = "Jupiter Binary Analysis Tool"
__date__        = "March 2018"
__author__      = "Andrew Blyth (andrew.blyth@southwales.ac.uk)"
#
#
#
class PE_Object:
    #
    type            = "__PE__"                                                  # This  is the file type to be analysed
    arch            = "__X86__"
    filename        = ""                                                        # This is the file name to be analysed.
    sections        = __FALSE__                                                 # Are Sections to be analysed   - FALSE
    segments        = __FALSE__                                                 # Are Segments to be analysed   - FALSE
    header          = __FALSE__                                                 # Print the header information  - FALSE
    DOS_HEADER      = __FALSE__
    NT_HEADERS      = __FALSE__
    FILE_HEADER     = __FALSE__
    OPTIONAL_HEADER = __FALSE__
    SECTION_TEXT    = __FALSE__
    SECTION_RDATA   = __FALSE__
    SECTION_DATA    = __FALSE__
    SECTION_RELOC   = __FALSE__
    FUNCTION_IMPORT = __FALSE__
    TLS             = __FALSE__
    BASERELOC       = __FALSE__
    BASERELOCVERB   = __FALSE__
    EXPORT          = __FALSE__
    RESOURCE        = __FALSE__
    #
    def __init__(self):
        type            = "__PE__"                                              # This  is the file type to be analysed.
        arch            = "__X86__"
        filename        = ""                                                    # This is the file name to be analysed.
        sections        = __FALSE__                                             # Are Sections to be analysed   - FALSE
        segments        = __FALSE__                                             # Are Segments to be analysed   - FALSE
        header          = __FALSE__                                             # Print the header information  - FALSE
        DOS_HEADER      = __FALSE__
        NT_HEADERS      = __FALSE__
        FILE_HEADER     = __FALSE__
        OPTIONAL_HEADER = __FALSE__
        SECTION_TEXT    = __FALSE__
        SECTION_RDATA   = __FALSE__
        SECTION_DATA    = __FALSE__
        SECTION_RELOC   = __FALSE__
        FUNCTION_IMPORT = __FALSE__
        TLS             = __FALSE__
        BASERELOC       = __FALSE__
        BASERELOCVERB   = __FALSE__
        EXPORT          = __FALSE__
        RESOURCE        = __FALSE__
    #
    def headerinfo(self):
        if (self.type == "__PE__"):
            self.__pe__ = pefile.PE(self.filename)
            #
            print "    Dump of file: " + self.filename
            if (self.__pe__.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE ):
                print "    PE Signature Found / File Type: EXECUTABLE IMAGE (32-Bit)\n"
            elif (self.__pe__.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS ):
                print "    PE Signature Found / File Type: EXECUTABLE IMAGE (64-Bit)\n"
            #
            if (self.DOS_HEADER):
                print self.__pe__.DOS_HEADER
                print ""
            if (self.NT_HEADERS):
                print self.__pe__.NT_HEADERS
                print ""
            if (self.FILE_HEADER):
                print self.__pe__.FILE_HEADER
                print ""
            if (self.OPTIONAL_HEADER):
                print self.__pe__.OPTIONAL_HEADER
                print ""
        elif (self.type == "__ELF__"):
            print "The ELF Type is currently not supported."
            exit()
        else:
            print "The File Type is currently not known"
            exit()
    #
    def sectioninfo(self):
        if (self.type == "__PE__"):
            self.__pe__ = pefile.PE(self.filename)
            for sect in self.__pe__.sections:
                if (self.SECTION_TEXT and (".text" in sect.Name)):
                    print sect
                    print ""
                    self.SECTION_TEXT = __FALSE__
                if (self.SECTION_DATA and (".data" in sect.Name)):
                    print sect
                    print ""
                    self.SECTION_DATA = __FALSE__
                if (self.SECTION_RDATA and (".rdata" in sect.Name)):
                    print sect
                    print ""
                    self.SECTION_RDATA = __FALSE__
                if (self.SECTION_RELOC and (".reloc" in sect.Name)):
                    print sect
                    print ""
                    self.SECTION_RELOC = __FALSE__
    #
    #
    #
    def importinfo(self):
        if (self.type == "__PE__"):
            self.__pe__ = pefile.PE(self.filename)
            print "[DIRECTORY_ENTRY_IMPORT]"
            for imp in self.__pe__.DIRECTORY_ENTRY_IMPORT:
                print imp.dll
                for func in imp.imports:
                    print "Ordinal:" + str(func.ordinal) + "  -  Bound:" + str(func.bound) + "  -  Name:" + str(func.name)
                print imp.struct
    #
    #
    #
    def disassembleinfo(self, arch):

        if (self.type == "__PE__"):
            self.__pe__ = pefile.PE(self.filename)
            self._SizeOfCode = self.__pe__.OPTIONAL_HEADER.SizeOfCode
            self._ImageBase  = self.__pe__.OPTIONAL_HEADER.ImageBase
            self._Start      = self.__pe__.OPTIONAL_HEADER.AddressOfEntryPoint
            self._BaseOfCode = self.__pe__.OPTIONAL_HEADER.BaseOfCode

            if (arch == "__MIP__"):
                if (self.__pe__.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE ):
                    cs   = Cs(CS_ARCH_MIPS, CS_MODE_MIP32)
                elif (self.__pe__.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS ):
                    cs   = Cs(CS_ARCH_MIPS, CS_MODE_MIP64)

            if (arch == "__X86__"):
                if (self.__pe__.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE ):
                    cs   = Cs(CS_ARCH_X86, CS_MODE_32)
                elif (self.__pe__.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS ):
                    cs   = Cs(CS_ARCH_X86, CS_MODE_64)

            if (arch == "__ARM__"):
                if (self.__pe__.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE ):
                    cs   = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                elif (self.__pe__.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS ):
                    cs   = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

            print "OPTIONAL_HEADER.ImageBase           : " + str(hex(self._ImageBase))
            print "OPTIONAL_HEADER.BaseOfCode:         : " + str(hex(self._BaseOfCode))
            print "OPTIONAL_HEADER.SizeOfCode:         : " + str(hex(self._SizeOfCode))
            print "OPTIONAL_HEADER.AddressOfEntryPoint : " + str(hex(self._Start))
            print ""

            data = self.__pe__.get_memory_mapped_image()[self._BaseOfCode:]
            for i in cs.disasm(data, ( self._BaseOfCode + self._ImageBase )):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    #
    #
    #
    def tlsinfo(self):
        if (self.type == "__PE__"):
            self.__pe__ = pefile.PE(self.filename)
            print "[DIRECTORY_ENTRY_TLS]"
            try:
                for tls in self.__pe__.DIRECTORY_ENTRY_TLS:
                    print tls.struct
            except AttributeError:
                print "No Information available in executable: " + self.filename
        if (self.type == "__ELF__"):
            print "To be Done"
    #
    #
    #
    def baselocation(self):
        if (self.type == "__PE__"):
            self.__pe__ = pefile.PE(self.filename)
            print "[DIRECTORY_ENTRY_BASERELOC]"
            try:
                for base in self.__pe__.DIRECTORY_ENTRY_BASERELOC:
                    print base.struct
                    if (self.BASERELOCVERB == __TRUE__):
                        for ent in base.entries:
                            print "    RELOCATION_TYPE[" + str(ent.type) + "] -- RVA[" + str(ent.rva) + "]"
            except AttributeError:
                print "No Information available in executable: " + self.filename
    #
    #
    #
    def export(self):
        if (self.type == "__PE__"):
            self.__pe__ = pefile.PE(self.filename)
            print "[DIRECTORY_ENTRY_EXPORT]"

            try:
                for exp in self.__pe__.DIRECTORY_ENTRY_EXPORT:
                    print exp.struct
                    print exp.symbols
            except AttributeError:
                print "No DIRECTORY_ENTRY_EXPORT Information available in executable: " + self.filename
    #
    #
    #
    def resource(self):
        if (self.type == "__PE__"):
            self.__pe__ = pefile.PE(self.filename)
            print "[DIRECTORY_ENTRY_RESOURCE]"
            try:
                print self.__pe__.DIRECTORY_ENTRY_RESOURCE
            except AttributeError:
                print "No Information DIRECTORY_ENTRY_RESOURCE available in executable: " + self.filename
#
#
#
def analysePE(jobject, arch):
    print "\nThe " + __title__ + " - Version" +  str(__version__) +" - Date: " + __date__ + "\n"

    if (jobject.header          == __TRUE__): jobject.headerinfo()
    if (jobject.sections        == __TRUE__): jobject.sectioninfo()
    if (jobject.segments        == __TRUE__): jobject.segmentsinfo()
    if (jobject.disassemble     == __TRUE__): jobject.disassembleinfo(arch)
    if (jobject.FUNCTION_IMPORT == __TRUE__): jobject.importinfo()
    if (jobject.TLS             == __TRUE__): jobject.tlsinfo()
    if (jobject.BASERELOC       == __TRUE__): jobject.baselocation()
    if (jobject.EXPORT          == __TRUE__): jobject.export()
    if (jobject.RESOURCE        == __TRUE__): jobject.resource()

    exit()
#
#
#
def analyseELF(eobject,filename, arch):
    print "\nThe " + __title__ + " - Version" +  str(__version__) +" - Date: " + __date__ + "\n"

    eobject.parse_file_header(filename)
    eobject.parse_program_header()
    eobject.parse_section_header()

    if (eobject.ELHEADER         == __TRUE__): eobject.display_file_header()
    if (eobject.ELFILEHEADER     == __TRUE__): eobject.display_program_header()
    if (eobject.ELFSECTIONHEADER == __TRUE__): eobject.display_section_header()
    if (eobject.sections_data    == __TRUE__): eobject.sdata()
    if (eobject.sections_text    == __TRUE__): eobject.stext()
    if (eobject.sections_rdata   == __TRUE__): eobject.srdata()
    if (eobject.sections_dis     == __TRUE__): eobject.diss(arch)
    if (eobject.sections_bss     == __TRUE__): eobject.sbss()

    exit()
#
#
# This function displays the version/author page for the Jupiter - Binary Analysis Tool.
def version():
    print "\nThe " + __title__
    print "         VERSION : " + str(__version__)
    print "         AUTHOR  : " + __author__
    print "         DATE    : " + __date__
    exit()
#
#
# This function displays the help page for the Jupiter - Binary Analysis Tool.
def help():
    print "\n" + __title__ + " Version: " + str(__version__) + "\n"
    print "usaage: jupiter [-a elf|pe][-f filename][-l][-lt][-lr][-ld][-ll][-i][-p][-pd]"
    print "                     [-pn][-pf][-po][-r][-v][-h|-?][-b][-bv][d][-e]"
    print "                     [-H][-L][-S][-St][-Sr][-Sd][-Sl][-D]"
    print "\nGENERAL OPTIONS:"
    print "  -a [pe|elf]            Select the file type to be analysed. The default "
    print "                             is: PE."
    print "  -A [x86|arm|mip|pcc]   Select the CPU architecture to be analysed.The "
    print "                             default is: x86."
    print "  -f [filename]          Select the file to analyse."
    print "  -v                     Display the version information about the Jupiter"
    print "                             Binary Analysis Tool and then quits."
    print "  -h|-?                  This options displays the help/manual page."
    print "\nPE SPECIFIC OPTIONS:"
    print "  -l                     Display ALL section information of the executable."
    print "  -b                     Display the base locations."
    print "  -bv                    Display base locations in a verbose format."
    print "  -d                     Disassemble text section of executable."
    print "  -e                     Display the export function table."
    print "  -lt                    Print IMAGE_SECTION_HEADER for the section .text"
    print "  -lr                    Print IMAGE_SECTION_HEADER for the section .rdata"
    print "  -ld                    Print IMAGE_SECTION_HEADER for the section .data"
    print "  -ll                    Print IMAGE_SECTION_HEADER for the section .reloc"
    print "  -i                     Display the list of imported functions"
    print "  -t                     Display TLS information on the executable."
    print "  -p                     Display ALL header information of the executable."
    print "  -pd                    Print IMAGE_DOS_HEADER info of the executable."
    print "  -pn                    Print IMAGE_NT_HEADERS info of the executable."
    print "  -pf                    Print IMAGE_FILE_HEADER info of the executable."
    print "  -po                    Print IMAGE_OPTIONAL_HEADER info of the executable."
    print "  -r                     Print DIRECTORY_ENTRY_RESOURCE for the executable."
    print "\nELF SPECIFIC OPTIONS:"
    print "  -H                     Display IMAGE_ELF_HEADER of the executable."
    print "  -L                     Display IMAGE_ELF_PROGRAM_HEADER of the executable."
    print "  -S                     Display IMAGE_ELF_SECTION_HEADER of the executable."
    print "  -St                    Display the Section Header Summary for .text"
    print "  -Sr                    Display the Section Header Summary for .rodata"
    print "  -Sd                    Display the Section Header Summary for .data"
    print "  -Sb                    Display the Section Header Summary for .bss"
    print "  -D                     Disassemble text section of executable."

    exit()
#
#
# The main function for the Jupiter - Binary Analysis Tool.
def main():
    # Define the global variables for the Jupiter - Binary Analysis Tool Version
    loop = 1                                                    # This is the input string sys.argv loop counter.
    jobj = PE_Object()
    sobj = ELF_Object()
    #
    if (len(sys.argv) == 1 ): help()
    while loop < len(sys.argv):
        if ( sys.argv[loop] == "-h"):   help()
        elif ( sys.argv[loop] == "-v"): version()
        elif ( sys.argv[loop] == "-?"): help()
        elif ( sys.argv[loop] == "-a"):
            loop = loop + 1
            if (len(sys.argv) == (loop)):
                print "ERROR: Error Parsing Command line - please specify the ARCHITECTURE type: [pe|elf]"
                exit()
            elif (sys.argv[loop] == "pe"):  jobj.type  = "__PE__"
            elif (sys.argv[loop] == "elf"): jobj.type = "__ELF__"
            else:
                print "ERROR: Error Parsing Command line - please specify the ARCHITECTURE type: [pe|elf]"
                exit()
        elif (sys.argv[loop] == "-A"):
            loop = loop + 1
            if (len(sys.argv) == (loop)):
                print "ERROR: Error Parsing Command line - please specify the ARCHITECTURE type: [pe|elf]"
                exit()
            elif (sys.argv[loop] == "x86"): jobj.type = "__X86__"
            elif (sys.argv[loop] == "arm"): jobj.type = "__ARM__"
            elif (sys.argv[loop] == "mip"): jobj.type = "__MIP__"
            else:
                print "ERROR: Error Parsing Command line - please specify the ARCHITECTURE type: [pe|elf]"
                exit()
        elif (sys.argv[loop] == "-L"): sobj.ELFILEHEADER     = __TRUE__
        elif (sys.argv[loop] == "-H"): sobj.ELHEADER         = __TRUE__
        elif (sys.argv[loop] == "-S"): sobj.ELFSECTIONHEADER = __TRUE__
        elif (sys.argv[loop] == "-l"):
            jobj.sections      = __TRUE__
            jobj.SECTION_RELOC = __TRUE__
            jobj.SECTION_DATA  = __TRUE__
            jobj.SECTION_RDATA = __TRUE__
            jobj.SECTION_TEXT  = __TRUE__
        elif (sys.argv[loop] == "-lt"):
            jobj.sections      = __TRUE__
            jobj.SECTION_TEXT  = __TRUE__
        elif (sys.argv[loop] == "-lr"):
            jobj.sections      = __TRUE__
            jobj.SECTION_RDATA = __TRUE__
        elif (sys.argv[loop] == "-ld"):
            jobj.sections      = __TRUE__
            jobj.SECTION_DATA  = __TRUE__
        elif (sys.argv[loop] == "-ll"):
            jobj.sections      = __TRUE__
            jobj.SECTION_RELOC = __TRUE__
        elif (sys.argv[loop] == "-f"):
            loop = loop + 1
            if (len(sys.argv) == (loop)):
                print "ERROR: Error Parsing Command line - please specify the FILENAME to be analysed."
                exit()
            elif (os.path.isfile(sys.argv[loop])): jobj.filename = sys.argv[loop]
            else:
                print "ERROR: Error Parsing Command line - FILENAME not found."
                exit()
        elif (sys.argv[loop] == "-p"):
            jobj.header             = __TRUE__
            jobj.DOS_HEADER         = __TRUE__
            jobj.NT_HEADERS         = __TRUE__
            jobj.FILE_HEADER        = __TRUE__
            jobj.OPTIONAL_HEADER    = __TRUE__
        elif (sys.argv[loop] == "-pd"):
            jobj.header             = __TRUE__
            jobj.DOS_HEADER         = __TRUE__
        elif (sys.argv[loop] == "-pn"):
            jobj.header             = __TRUE__
            jobj.NT_HEADERS         = __TRUE__
        elif (sys.argv[loop] == "-pf"):
            jobj.header             = __TRUE__
            jobj.FILE_HEADER        = __TRUE__
        elif (sys.argv[loop] == "-po"):
            jobj.header             = __TRUE__
            jobj.OPTIONAL_HEADER    = __TRUE__
        elif (sys.argv[loop] == "-i"): jobj.FUNCTION_IMPORT    = __TRUE__
        elif (sys.argv[loop] == "-t"): jobj.TLS                = __TRUE__
        elif (sys.argv[loop] == "-b"): jobj.BASERELOC          = __TRUE__
        elif (sys.argv[loop] == "-bv"):
            jobj.BASERELOC          = __TRUE__
            jobj.BASERELOCVERB      = __TRUE__
        elif (sys.argv[loop] == "-e"): jobj.EXPORT             = __TRUE__
        elif (sys.argv[loop] == "-d"): jobj.disassemble        = __TRUE__
        elif (sys.argv[loop] == "-r"): jobj.RESOURCE           = __TRUE__
        elif (sys.argv[loop] == "-St"): sobj.sections_text     = __TRUE__
        elif (sys.argv[loop] == "-Sr"): sobj.sections_rdata    = __TRUE__
        elif (sys.argv[loop] == "-Sd"): sobj.sections_data     = __TRUE__
        elif (sys.argv[loop] == "-Sb"): sobj.sections_bss      = __TRUE__
        elif (sys.argv[loop] == "-D"): sobj.sections_dis       = __TRUE__
        else: exit()
        #
        loop = loop + 1
    if (jobj.filename == ""):
        print "ERROR: Error Parsing Command line - FILENAME not found. Please use the -f option."
        exit()
    # Now run the analyse routines on the filename specified and display the results.
    if (jobj.type == "__PE__"):
        analysePE(jobj,jobj.arch)
    elif (jobj.type == "__ELF__"):
        analyseELF(sobj, jobj.filename,jobj.arch)
#
#
# Make surethe program is being executed correctly with if __name__ == "__main__": main()
if __name__ == "__main__":
    try:
        main()
    except:
        exit()
#
#
# The END of the source code for the Jupiter - Binary Analysis Tool.
