# readeck
This is the set of Tools to support decompilation and reverse engineering

Jupiter Binary Analysis Tool Version: 1.0

usaage: jupiter [-a elf|pe][-f filename][-l][-lt][-lr][-ld][-ll][-i][-p][-pd]
                     [-pn][-pf][-po][-r][-v][-h|-?][-b][-bv][d][-e]
                     [-H][-L][-S][-St][-Sr][-Sd][-Sl][-D]

GENERAL OPTIONS:
  -a [pe|elf]            Select the file type to be analysed. The default
                             is: PE.
  -A [x86|arm|mip|pcc]   Select the CPU architecture to be analysed.The
                             default is: x86.
  -f [filename]          Select the file to analyse.
  -v                     Display the version information about the Jupiter
                             Binary Analysis Tool and then quits.
  -h|-?                  This options displays the help/manual page.

PE SPECIFIC OPTIONS:
  -l                     Display ALL section information of the executable.
  -b                     Display the base locations.
  -bv                    Display base locations in a verbose format.
  -d                     Disassemble text section of executable.
  -e                     Display the export function table.
  -lt                    Print IMAGE_SECTION_HEADER for the section .text
  -lr                    Print IMAGE_SECTION_HEADER for the section .rdata
  -ld                    Print IMAGE_SECTION_HEADER for the section .data
  -ll                    Print IMAGE_SECTION_HEADER for the section .reloc
  -i                     Display the list of imported functions
  -t                     Display TLS information on the executable.
  -p                     Display ALL header information of the executable.
  -pd                    Print IMAGE_DOS_HEADER info of the executable.
  -pn                    Print IMAGE_NT_HEADERS info of the executable.
  -pf                    Print IMAGE_FILE_HEADER info of the executable.
  -po                    Print IMAGE_OPTIONAL_HEADER info of the executable.
  -r                     Print DIRECTORY_ENTRY_RESOURCE for the executable.

ELF SPECIFIC OPTIONS:
  -H                     Display IMAGE_ELF_HEADER of the executable.
  -L                     Display IMAGE_ELF_PROGRAM_HEADER of the executable.
  -S                     Display IMAGE_ELF_SECTION_HEADER of the executable.
  -St                    Display the Section Header Summary for .text
  -Sr                    Display the Section Header Summary for .rodata
  -Sd                    Display the Section Header Summary for .data
  -Sb                    Display the Section Header Summary for .bss
  -D                     Disassemble text section of executable.
