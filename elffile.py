#
#
# This is the Parser for the ELF binary - Andrew.Blyth@southwales.ac.uk (March 2018)
#
#
#
#
import struct
import mmap
from elfutilities import *
from capstone import *
#
#
#
__FALSE__ = 0
__TRUE__  = 1
#
#
# Define the ELF Object that the ELF file will be read and parsed into. Key attributed are:
#
#   self.elf_header     A dictionary of the elf file header.
#
#   self.elf_pheader    An array of dictionaries, where each dictionary is a program header
#
#   self.elf_sheader    An array of dictionaries, where each dictionary is a section header
#
#   self.elf_sections  An dictionaries of dictionaries, where each dictionary is a section header
#
#   self.e_phoff        Points to the start of the program header table (Size: Two bytes).
#
#   self.e_phnum        Contains the number of entries in the program header table (Size: Two bytes).
#
#
#
class Section:
    __fname     = ""
    __name      = 0
    __type      = 0
    __flags     = 0
    __addr      = 0
    __offset    = 0
    __size      = 0
    __link      = 0
    __info      = 0
    __addralign = 0
    __entsize   = 0

    def __init__(self,fname, name, type, flags, addr, offset, size, link, info, addralign, entsize):
        self.__fname     = fname
        self.__name      = name
        self.__type      = type
        self.__flags     = flags
        self.__addr      = addr
        self.__offset    = offset
        self.__size      = size
        self.__link      = link
        self.__info      = info
        self.__addralign = addralign
        self.__entsize   = entsize

    def get_fname(self): return self.__fname

    def get_name(self): return self.__name

    def get_type(self): return self.__type

    def get_flags(self): return self.__flags

    def get_addr(self): return self.__addr

    def get_offset(self): return self.__offset

    def get_size(self): return self.__size

    def get_link(self): return self.__link

    def get_info(self): return self.__info

    def get_addralign(self): return self.__addralign

    def get_entsize(self): return self.__entsize
#
#
#
class ELF_Object:
    #
    #
    #
    __IMAGE_ELF_HEADER_32FORMAT__ = ('4s,e_magic', 'B,e_class', 'B,e_data', 'B,e_version', 'B,e_osabi',
                                       'B,e_abiversion', '7s,e_pad', 'H,e_type', 'H,e_machine', 'I,e_version',
                                       'I,e_entry', 'I,e_phoff', 'I,e_shoff', 'I,e_flags', 'H,e_ehsize',
                                       'H,e_phentsize', 'H,e_phnum', 'H,e_shentsize', 'H,e_shnum', 'H,e_shstrndx')
    #
    #
    #
    __IMAGE_ELF_HEADER_64FORMAT__ = ('4s,e_magic', 'B,e_class', 'B,e_data', 'B,e_version', 'B,e_osabi',
                                       'B,e_abiversion', '7s,e_pad', 'H,e_type', 'H,e_machine', 'I,e_version',
                                       'Q,e_entry', 'Q,e_phoff', 'Q,e_shoff', 'I,e_flags', 'H,e_ehsize',
                                       'H,e_phentsize', 'H,e_phnum', 'H,e_shentsize', 'H,e_shnum', 'H,e_shstrndx')
    #
    #
    #
    __IMAGE_PROGRAM_HEADER_32FORMAT__ = ('I,p_type', 'I,p_offset', 'I,p_vaddr', 'I,p_paddr',
                                         'I,p_filesz', 'I,p_memsz', 'I,p_flags','I,p_align')
    #
    #
    #
    __IMAGE_PROGRAM_HEADER_64FORMAT__ = ('I,p_type', 'I,p_flags', 'Q,p_offset', 'Q,p_vaddr', 'Q,p_paddr',
                                         'Q,p_filesz', 'Q,p_memsz', 'Q,p_align')
    #
    #
    #
    __IMAGE_SECTION_HEADER_32FORMAT__ = ('I,sh_name', 'I,sh_type',' I,sh_flags',' I,sh_addr',' I,sh_offset',
                                         'I,sh_size', 'I,sh_link', 'I,sh_info', 'I,sh_addralign', 'I,sh_entsize')
    #
    #
    #
    __IMAGE_SECTION_HEADER_64FORMAT__ = ('I,sh_name', 'I,sh_type','Q,sh_flags','Q,sh_addr','Q,sh_offset',
                                         'Q,sh_size', 'I,sh_link', 'I,sh_info', 'Q,sh_addralign', 'Q,sh_entsize')
    #
    #
    #
    __PROGRAM_FLAGS__ = [
        ('0x0',                             '---'),
        ('0x1',                             '--x'),
        ('0x2',                             '-w-'),
        ('0x3',                             '_wx'),
        ('0x4',                             'r--'),
        ('0x5',                             'r-x'),
        ('0x6',                             'rw-'),
        ('0x7',                             'rwx')]
    #
    #
    #
    __SIZE__ = {'c': '1', 'H': '2', 'I': '4', 'Q': '8', '4s': '4'}
    #
    #
    #
    __PROGRAM_TYPES__ = [
        ('PT_NULL',                         0x00000000),
        ('PT_LOAD',                         0x00000001),
        ('PT_DYNAMIC',                      0x00000002),
        ('PT_INTERP',                       0x00000003),
        ('PT_NOTE',                         0x00000004),
        ('PT_SHLIB',                        0x00000005),
        ('PT_PHDR',                         0x00000006),
        ('PT_LOOS',                         0x60000000),
        ('GNU_EH_FRAME',                    0x6474E550),
        ('GNU_STACK',                       0x6474E551),
        ('GNU_RELRO',                       0x6474E552),
        ('PT_HIOS',                         0x6FFFFFFF),
        ('PT_LOPROC',                       0x70000000),
        ('PT_HIPROC',                       0x7FFFFFFF)]
    #
    #
    #
    __SYSTEM_TYPES__ = [
        ('SYSTEM V',                        0x00),          # Defined for the System-V Operating System - The Original
        ('HP-UX',                           0x01),          # Defined for the HP-UX Operating System
        ('NETBSD',                          0x02),          # Defined for the NetBSD Operating System
        ('LINUX',                           0x03),          # Defined for the Linux Operating System
        ('GNU HURD',                        0x04),
        ('UNKNOWN',                         0x05),
        ('SOLARIS',                         0x06),          # Defined for the Solaris Operating System
        ('AIX',                             0x07),          # Defined for the AIX Operating System
        ('IRIX',                            0x08),          # Defined for the SGI IRIX Operating System
        ('FREEBSD',                         0x09),          # Defined for the FreeBSD Operating System
        ('TRU64',                           0x0A),
        ('NOVEL MODESTO',                   0x0B),
        ('OPENBSD',                         0x0C),          # Defined for the OpenBSD Operating System
        ('OPEN VMS',                        0x0D),          # Defined for the Open VMS Operating System
        ('NONSTOP KERNEL',                  0x0E),
        ('AROS',                            0x0F),
        ('FENIX OS',                        0x10),
        ('CLOUDABI',                        0x11)]
    #
    #
    __TYPES__ = [
        ('RELOCATABLE',                     0x01),
        ('EXECUTABLE',                      0x02),          # Means the file is an executable file
        ('SHARED',                          0x03),          # Means the file is an shared object / library
        ('CORE',                            0x04)]
    #
    #
    #
    __MACHINES__ = [
        ('NO SPECIFIC MACHINE',             0x00),
        ('AT&T WE 32100',                   0x01),
        ('SPARC',                           0x02),
        ('X86',                             0x03),
        ('MIPS',                            0x08),
        ('POWERPC',                         0x14),
        ('S390',                            0x16),
        ('ARM',                             0x28),
        ('SUPERH',                          0x2A),
        ('IA-64',                           0x32),
        ('X86-64',                          0x3E),
        ('AARCH64',                         0xB7),
        ('RISC-V',                          0xF3)]
    #
    #
    #
    __SECTION__HEADER_INFO__ = [
        (0x00,          'SHT_NULL',             'Section header table entry unused'),
        (0x01,          'SHT_PROGBITS',         'Program data'),
        (0x02,          'SHT_SYMTAB',           'Symbol table'),
        (0x03,          'SHT_STRTAB',           'String table'),
        (0x04,          'SHT_RELA',             'Relocation entries with addends'),
        (0x05,          'SHT_HASH',             'Symbol hash table'),
        (0x06,          'SHT_DYNAMIC',          'Dynamic linking information'),
        (0x07,          'SHT_NOTE',             'Notes'),
        (0x08,          'SHT_NOBITS',           'Program space with no data (bss)'),
        (0x09,          'SHT_REL',              'Relocation entries, no addends'),
        (0x0A,          'SHT_SHLIB',            'Reserved'),
        (0x0B,          'SHT_DYNSYM',           'Dynamic linker symbol table'),
        (0x0E,          'SHT_INIT_ARRAY',       'Array of constructors'),
        (0x0F,          'SHT_FINI_ARRAY',       'Array of destructors'),
        (0x10,          'SHT_PREINIT_ARRAY',    'Array of pre-constructors'),
        (0x11,          'SHT_GROUP',            'Section group'),
        (0x12,          'SHT_SYMTAB_SHNDX',     'Extended section indeces'),
        (0x13,          'SHT_NUM',              'Number of defined types'),
        (0x60000000,    'SHT_LOOS',             'Start OS-specific')]
    #
    #
    #
    __SECTION__HEADER_FLAGS__ = [
        (0x0,           'NULL',                              'No Flags Set'),
        (0x1,           'SHF_WRITE',                         'Writable'),
        (0x2,           'SHF_ALLOC',                         'Occupies memory during execution'),
        (0x3,           'SHF_WRITE/SHF_ALLOC',               'Writable and Occupies memory during execution'),
        (0x4,           'SHF_EXECINSTR',                     'Executable'),
        (0x5,           'SHF_WRITE/SHF_EXECINSTR',           'Writable and Executable'),
        (0x6,           'SHF_ALLOC/SHF_EXECINSTR',           'Executable and Occupies memory during execution'),
        (0x7,           'SHF_WRITE/SHF_ALLOC/SHF_EXECINSTR', 'Writable, Executable & Occupies memory during execution'),
        (0x10,          'SHF_MERGE',                         'Might be merged'),
        (0x20,          'SHF_STRINGS',                       'Contains nul-terminated strings'),
        (0x40,          'SHF_INFO_LINK',                     'sh_info - contains SHT index'),
        (0x80,          'SHF_LINK_ORDER',                    'Preserve order after combining'),
        (0x100,         'SHF_OS_NONCONFORMING',              'Non-standard OS specific handling required'),
        (0x200,         'SHF_GROUP',                         'Section is member of a group'),
        (0x400,         'SHF_TLS',                           'Section hold thread-local data'),
        (0x0ff00000,    'SHF_MASKOS',                        'OS-specific')]
    #
    #
    #
    def program_header_offset(self,type, member):
        if (type == 64):
            for i in self.__IMAGE_PROGRAM_HEADER_64FORMAT__:
                if (i.split(',')[1] == member): return self.__SIZE__[i.split(',')[0]]
        elif (type == 32):
            for i in self.__IMAGE_PROGRAM_HEADER_32FORMAT__:
                if (i.split(',')[1] == member): return self.__SIZE__[i.split(',')[0]]
        else:
            return 0
    #
    #
    #
    def parse_program_header(self):

        self.e_phnum = self.elf_header['e_phnum']
        for program_header_counter in range(self.e_phnum):

            self.__format__ = '<'
            self.__attrlt__ = []

            if (self.elf_header['e_class'] == 2):                               # Set the File Header to 64-Bit Mode
                lower_offset = self.e_phoff + (self.e_phentsize * program_header_counter)
                upper_offet  = self.e_phoff + (self.e_phentsize * (program_header_counter + 1))
                elf_pheader_data = self.__data__[lower_offset:upper_offet]

                for elmt in self.__IMAGE_PROGRAM_HEADER_64FORMAT__:
                    elmt_type, elmt_name = elmt.split(',', 1)
                    self.__format__ += elmt_type
                    self.__attrlt__.append(elmt_name)

                self.elf_pheader = self.elf_pheader + [self.__unpack_data__(elf_pheader_data)]

            elif (self.elf_header['e_class'] == 1):                               # Set the File Header to 32-Bit Mode
                lower_offset = self.e_phoff + (self.e_phentsize * program_header_counter)
                upper_offet = self.e_phoff + (self.e_phentsize * (program_header_counter + 1))
                elf_pheader_data = self.__data__[lower_offset:upper_offet]

                for elmt in self.__IMAGE_PROGRAM_HEADER_32FORMAT__:
                    elmt_type, elmt_name = elmt.split(',', 1)
                    self.__format__ += elmt_type
                    self.__attrlt__.append(elmt_name)

                self.elf_pheader = self.elf_pheader + [self.__unpack_data__(elf_pheader_data)]
    #
    #
    #
    def parse_file_header(self,fname):

        self.__fileid__ = open(fname, 'rb')
        self.__filnod__ = self.__fileid__.fileno()

        if hasattr(mmap, 'MAP_PRIVATE'):                                    # Set the File Header to 32-Bit Mode
            self.__data__ = mmap.mmap(self.__filnod__, 0, mmap.MAP_PRIVATE)
        else:
            raise ValueError('Not an ELF File')

        elf_header_data = self.__data__[:52]
        if len(elf_header_data) != 52:
            raise ValueError('Unable to read the ELF Header')

        for elmt in self.__IMAGE_ELF_HEADER_32FORMAT__:
            elmt_type, elmt_name = elmt.split(',', 1)
            self.__format__ += elmt_type
            self.__attrlt__.append(elmt_name)

        self.elf_header = self.__unpack_data__(elf_header_data)

        if (self.elf_header['e_class'] == 2):                               # Set the File Header to 64-Bit Mode
            self.__format__ = '<'
            self.__attrlt__  = []

            elf_header_data = self.__data__[:64]
            if len(elf_header_data) != 64:
                raise ValueError('Unable to read the ELF Header')

            for elmt in self.__IMAGE_ELF_HEADER_64FORMAT__ :
                elmt_type, elmt_name = elmt.split(',', 1)
                self.__format__ += elmt_type
                self.__attrlt__.append(elmt_name)

            self.elf_header = self.__unpack_data__(elf_header_data)

        self.e_phnum     = self.elf_header['e_phnum']
        self.e_phoff     = self.elf_header['e_phoff']
        self.e_phentsize = self.elf_header['e_phentsize']

    #
    #
    #
    def get_elf_file_header(self): return self.elf_header
    #
    #
    #
    def get_elf_program_header(self): return self.elf_pheader
    #
    #
    #
    def get_sections(self): return self.sections
    #
    #
    #
    def __unpack_data__(self,header_data):
        return dict(zip( self.__attrlt__,struct.unpack(str(self.__format__), header_data)))
    #
    #
    #
    def display_file_header(self):
        print "[IMAGE_ELF_FILE_HEADER]"
        print "0x00      0x00    e_magic                        : 0x" \
              + str(toHex(self.elf_header['e_magic']))[6:] \
              + " (" + str(self.elf_header['e_magic'])[1:4] + ")"
        if (self.elf_header['e_class'] == 2):
            print "0x04      0x04    e_class                        : 0x" + str(self.elf_header['e_class']) \
                  + " (64 Bit Mode)"
        elif (self.elf_header['e_class'] == 1):
            print "0x04      0x04    e_class                        : 0x" + str(self.elf_header['e_class']) \
                  + " (32 Bit Mode)"
        else:
            print "0x04      0x04    e_class                        : 0x" + str(self.elf_header['e_class']) \
                  + " (Unknowm Bit Mode)"
        print "0x05      0x05    e_data                         : 0x" + str(self.elf_header['e_data'])
        print "0x06      0x06    e_version                      : 0x" + str(self.elf_header['e_version'])
        for (system,enum) in self.__SYSTEM_TYPES__:
            if (enum == self.elf_header['e_osabi']):
                print "0x07      0x07    e_osabi                        : 0x" + str(self.elf_header['e_osabi']) \
                    + " (" + system + ")"
        print "0x08      0x08    e_abiversion                   : 0x" + str(self.elf_header['e_abiversion'])
        print "0x09      0x09    e_pad                          : 0x" + str(toHex(self.elf_header['e_pad'])).upper()
        for (type, enum) in self.__TYPES__:
            if (enum == self.elf_header['e_type']):
                print "0x10      0x10    e_type                         : 0x" + str(self.elf_header['e_type']) \
                      + " (" + type + ")"
        for (machine, enum) in self.__MACHINES__ :
            if (enum == self.elf_header['e_machine']):
                print "0x12      0x12    e_machine                      : " + str(hex(self.elf_header['e_machine'])) \
                        + " (" + machine + ")"
        print "0x14      0x14    e_version                      : 0x" + str(self.elf_header['e_version'])
        if (self.elf_header['e_class'] == 2):
            print "0x18      0x18    e_entry                        : " + str(hex(self.elf_header['e_entry']))
            print "0x20      0x20    e_phoff                        : " + str(hex(self.elf_header['e_phoff']))
            print "0x28      0x28    e_shoff                        : " + str(hex(self.elf_header['e_shoff']))
            print "0x30      0x30    e_flags                        : " + str(hex(self.elf_header['e_flags']))
            print "0x34      0x34    e_ehsize                       : " + str(hex(self.elf_header['e_ehsize']))
            print "0x36      0x36    e_phentsize                    : " + str(hex(self.elf_header['e_phentsize']))
            print "0x38      0x38    e_phnum                        : " + str(hex(self.elf_header['e_phnum']))
            print "0x3A      0x3A    e_shentsize                    : " + str(hex(self.elf_header['e_shentsize']))
            print "0x3C      0x3C    e_shnum                        : " + str(hex(self.elf_header['e_shnum']))
            print "0x3E      0x3E    e_shstrndx                     : " + str(hex(self.elf_header['e_shstrndx']))
        elif (self.elf_header['e_class'] == 1):
            print "0x18      0x18    e_entry                        : " + str(hex(self.elf_header['e_entry']))
            print "0x1C      0x1C    e_phoff                        : " + str(hex(self.elf_header['e_phoff']))
            print "0x20      0x20    e_shoff                        : " + str(hex(self.elf_header['e_shoff']))
            print "0x24      0x24    e_flags                        : " + str(hex(self.elf_header['e_flags']))
            print "0x28      0x28    e_ehsize                       : " + str(hex(self.elf_header['e_ehsize']))
            print "0x2A      0x2A    e_phentsize                    : " + str(hex(self.elf_header['e_phentsize']))
            print "0x2C      0x2C    e_phnum                        : " + str(hex(self.elf_header['e_phnum']))
            print "0x2E      0x2E    e_shentsize                    : " + str(hex(self.elf_header['e_shentsize']))
            print "0x30      0x30    e_shnum                        : " + str(hex(self.elf_header['e_shnum']))
            print "0x32      0x32    e_shstrndx                     : " + str(hex(self.elf_header['e_shstrndx']))
    #
    #
    #
    def __offset_calulation(self, offset_counter, type):
        if (self.elf_header['e_class'] == 1):
            return offset_counter + int(self.program_header_offset(32, type))
        else:
            return offset_counter + int(self.program_header_offset(64, type))
    #
    #
    #
    def display_phheader(self, program_header_counter):
        self._program_header_done = __FALSE__
        for (type, pid) in self.__PROGRAM_TYPES__:
            if (pid == self.elf_pheader[program_header_counter]['p_type']):
                print "\n[IMAGE_ELF_PROGRAM_HEADER]: " + type
                offset_counter = self.e_phoff + ( program_header_counter * self.elf_header['e_phentsize'])
                self._program_header_done  = __TRUE__
                print str(hex(offset_counter)) + "      0x00    p_type                         : " \
                      + str(hex(self.elf_pheader[program_header_counter]['p_type'])) + " (" + type + ")"

        if (self._program_header_done == 0):
            print "\n[IMAGE_ELF_PROGRAM_HEADER]: NOT KNOWN (" + \
                str(hex(self.elf_pheader[program_header_counter]['p_type'])) + ")"
            print str(hex(offset_counter)) + "      0x00    p_type                         : " \
                + str(hex(self.elf_pheader[program_header_counter]['p_type'])) + " (NOT KNOWN)"

        if (self.elf_header['e_class'] == 1):
            offset_counter = offset_counter + int(self.program_header_offset(32, 'p_type'))
        else:
            offset_counter = offset_counter + int(self.program_header_offset(64, 'p_type'))

        for (id, flags) in self.__PROGRAM_FLAGS__:
            if (id == hex(self.elf_pheader[program_header_counter]['p_flags'])):
                print str(hex(offset_counter)) + "      0x04    p_flags                        : " \
                    + str(hex(self.elf_pheader[program_header_counter]['p_flags'])) + " (" + flags + ")"
                offset_counter = self.__offset_calulation(offset_counter,'p_flags')

        print str(hex(offset_counter)) + "      0x08    p_offset                       : " \
            + str(hex(self.elf_pheader[program_header_counter]['p_offset']))
        offset_counter = self.__offset_calulation(offset_counter, 'p_offset')

        print str(hex(offset_counter)) + "      0x10    p_vaddr                        : " \
            + str(hex(self.elf_pheader[program_header_counter]['p_vaddr']))
        offset_counter = self.__offset_calulation(offset_counter, 'p_vaddr')

        print str(hex(offset_counter)) + "      0x18    p_paddr                        : " \
            + str(hex(self.elf_pheader[program_header_counter]['p_paddr']))
        offset_counter = self.__offset_calulation(offset_counter, 'p_paddr')

        print str(hex(offset_counter)) + "      0x20    p_filesz                       : " \
            + str(hex(self.elf_pheader[program_header_counter]['p_filesz']))
        offset_counter = self.__offset_calulation(offset_counter, 'p_filesz')

        print str(hex(offset_counter)) + "      0x28    p_memsz                        : " \
            + str(hex(self.elf_pheader[program_header_counter]['p_memsz']))
        offset_counter = self.__offset_calulation(offset_counter, 'p_memsz')

        print str(hex(offset_counter)) + "      0x30    p_align                        : " \
            + str(hex(self.elf_pheader[program_header_counter]['p_align']))
    #
    #
    #
    def display_program_header(self):
        offset_counter = self.e_phoff
        for program_header_counter in range(self.e_phnum):
            self.display_phheader(program_header_counter)
    #
    #
    #
    def parse_section_header(self):
        self.e_shnum        = self.elf_header['e_shnum']
        self.e_shentsize    = self.elf_header['e_shentsize']
        self.e_shoff        = self.elf_header['e_shoff']
        self.__format__     = '<'
        self.__attrlt__     = []
        self.elf_sheader    = []

        if (self.elf_header['e_shoff'] == 0):  return self.elf_sheader        # No Sections Found

        lower_offset = self.elf_header['e_shoff']
        upper_offset = (self.e_shnum * self.e_shentsize) + lower_offset

        if (self.elf_header['e_class'] == 2):                                   # Set the File Header to 64-Bit Mode

            elf_sheader_data = self.__data__[lower_offset:upper_offset]

            for elmt in self.__IMAGE_SECTION_HEADER_64FORMAT__:
                elmt_type, elmt_name = elmt.split(',', 1)
                self.__format__ += elmt_type
                self.__attrlt__.append(elmt_name)

            for item in range(self.e_shnum):
                loffset = (item * self.e_shentsize)
                uoffset = ((item + 1) * self.e_shentsize)

                self.elf_sheader = self.elf_sheader + [self.__unpack_data__(elf_sheader_data[loffset:uoffset])]

        if (self.elf_header['e_class'] == 1):                                   # Set the File Header to 32-Bit Mode

            elf_sheader_data = self.__data__[lower_offset:upper_offset]

            for elmt in self.__IMAGE_SECTION_HEADER_32FORMAT__:
                elmt_type, elmt_name = elmt.split(',', 1)
                self.__format__ += elmt_type
                self.__attrlt__.append(elmt_name)

            for item in range(self.e_shnum):
                loffset = (item * self.e_shentsize)
                uoffset = ((item + 1) * self.e_shentsize)

                self.elf_sheader = self.elf_sheader + [self.__unpack_data__(elf_sheader_data[loffset:uoffset])]

        for header in self.elf_sheader:
            if ((header['sh_type'] == 0x03) and (header['sh_flags'] == 0x00)):
                self.sect['shstrtag'] = header

        string_lower = self.sect['shstrtag']['sh_offset']
        string_upper = self.sect['shstrtag']['sh_offset'] + self.sect['shstrtag']['sh_size']
        for header in self.elf_sheader:
            self.sections[self.__data__[(string_lower + header['sh_name']):string_upper].split('\x00')[0]] = \
                Section(self.__data__[(string_lower + header['sh_name']):string_upper].split('\x00')[0],
                    header['sh_name'], header['sh_type'], header['sh_flags'], header['sh_addr'],
                    header['sh_offset'], header['sh_size'], header['sh_link'], header['sh_info'],
                    header['sh_addralign'], header['sh_entsize'])
    #
    #
    #
    def display_section_header(self):
        counter = self.e_shoff

        if (self.elf_header['e_class'] == 2):                                   # Set the File Header to 64-Bit Mode
            for item in self.sections:

                print "\n[IMAGE_ELF_SECTION_HEADER]: " + str(self.sections[item].get_fname())
                print hex(counter) + "      0x00    sh_name                      :" + \
                      str(hex(self.sections[item].get_name()))
                counter = counter + 4
                done = 0
                for flagid, meaning, _ in self.__SECTION__HEADER_INFO__:
                    if (self.sections[item].get_type() == flagid ):
                        done = 1
                        print hex(counter) + "      0x04    sh_type                      :" + \
                            str(hex(self.sections[item].get_type())) + " (" + meaning + ")"
                if (done == 0):print hex(counter) + "      0x04    sh_type                      :" + \
                            str(hex(self.sections[item].get_type()))
                counter = counter + 4
                for flagid, meaning, _ in self.__SECTION__HEADER_FLAGS__:
                    if (self.sections[item].get_flags() == flagid ):
                        print hex(counter) + "      0x08    sh_flags                     :" + \
                            str(hex(self.sections[item].get_flags())) + " (" + meaning + ")"
                counter = counter + 8
                print hex(counter) + "      0x10    sh_addr                      :" + \
                      str(hex(self.sections[item].get_addr()))
                counter = counter + 8
                print hex(counter) + "      0x18    sh_offset                    :" + \
                      str(hex(self.sections[item].get_offset()))
                counter = counter + 8
                print hex(counter) + "      0x20    sh_size                      :" + \
                      str(hex(self.sections[item].get_size()))
                counter = counter + 4
                print hex(counter) + "      0x28    sh_link                      :" + \
                      str(hex(self.sections[item].get_link()))
                counter = counter + 4
                print hex(counter) + "      0x2C    sh_info                      :" + \
                      str(hex(self.sections[item].get_info()))
                counter = counter + 8
                print hex(counter) + "      0x30    sh_addralign                 :" + \
                      str(hex(self.sections[item].get_addralign()))
                counter = counter + 8
                print hex(counter) + "      0x38    sh_entsiz                    :" + \
                      str(hex(self.sections[item].get_entsize()))
                counter = counter + 8

        if (self.elf_header['e_class'] == 1):                                   # Set the File Header to 32-Bit Mode
            for item in self.sections:

                print "\n[IMAGE_ELF_SECTION_HEADER]: " + str(self.sections[item].get_fname())
                print hex(counter) + "      0x00    sh_name                      :" + \
                      str(hex(self.sections[item].get_name()))
                counter = counter + 4
                done = 0
                for flagid, meaning, _ in self.__SECTION__HEADER_INFO__:
                    if (self.sections[item].get_type() == flagid):
                        done = 1
                        print hex(counter) + "      0x04    sh_type                      :" + \
                              str(hex(self.sections[item].get_type())) + " (" + meaning + ")"
                if (done == 0): print hex(counter) + "      0x04    sh_type                      :" + \
                                      str(hex(self.sections[item].get_type()))
                counter = counter + 4
                for flagid, meaning, _ in self.__SECTION__HEADER_FLAGS__:
                    if (self.sections[item].get_flags() == flagid):
                        print hex(counter) + "      0x08    sh_flags                     :" + \
                              str(hex(self.sections[item].get_flags())) + " (" + meaning + ")"
                counter = counter + 4
                print hex(counter) + "      0x0C    sh_addr                      :" + \
                      str(hex(self.sections[item].get_addr()))
                counter = counter + 4
                print hex(counter) + "      0x10    sh_offset                    :" + \
                      str(hex(self.sections[item].get_offset()))
                counter = counter + 4
                print hex(counter) + "      0x14    sh_size                      :" + \
                      str(hex(self.sections[item].get_size()))
                counter = counter + 4
                print hex(counter) + "      0x18    sh_link                      :" + \
                      str(hex(self.sections[item].get_link()))
                counter = counter + 4
                print hex(counter) + "      0x1C    sh_info                      :" + \
                      str(hex(self.sections[item].get_info()))
                counter = counter + 4
                print hex(counter) + "      0x20    sh_addralign                 :" + \
                      str(hex(self.sections[item].get_addralign()))
                counter = counter + 4
                print hex(counter) + "      0x24    sh_entsize                   :" + \
                      str(hex(self.sections[item].get_entsize()))
                counter = counter + 4
    #
    #
    #
    def stext(self):
        print "[TEXT SECTION]"
        for item in self.sections:
            if (self.sections[item].get_fname() == '.text'):
                print "Section Address : " + str(hex(self.sections[item].get_addr()))
                print "Section Offset  : " + str(hex(self.sections[item].get_offset()))
                print "Section Size    : " + str(hex(self.sections[item].get_size()))
                for flagid, meaning, _ in self.__SECTION__HEADER_INFO__:
                    if (self.sections[item].get_type() == flagid ):
                        print "Section Type    : " + meaning
                for flagid, meaning, _ in self.__SECTION__HEADER_FLAGS__:
                    if (self.sections[item].get_flags() == flagid):
                        print "Section Flags   : " + meaning
    #
    #
    #
    def srdata(self):
        print "[RODATA SECTION]"
        for item in self.sections:
            if (self.sections[item].get_fname() == '.rodata'):
                print "Section Address : " + str(hex(self.sections[item].get_addr()))
                print "Section Offset  : " + str(hex(self.sections[item].get_offset()))
                print "Section Size    : " + str(hex(self.sections[item].get_size()))
                for flagid, meaning, _ in self.__SECTION__HEADER_INFO__:
                    if (self.sections[item].get_type() == flagid ):
                        print "Section Type    : " + meaning
                for flagid, meaning, _ in self.__SECTION__HEADER_FLAGS__:
                    if (self.sections[item].get_flags() == flagid):
                        print "Section Flags   : " + meaning
    #
    #
    #
    def sdata(self):
        print "[DATA SECTION]"
        for item in self.sections:
            if (self.sections[item].get_fname() == '.data'):
                print "Section Address : " + str(hex(self.sections[item].get_addr()))
                print "Section Offset  : " + str(hex(self.sections[item].get_offset()))
                print "Section Size    : " + str(hex(self.sections[item].get_size()))
                for flagid, meaning, _ in self.__SECTION__HEADER_INFO__:
                    if (self.sections[item].get_type() == flagid ):
                        print "Section Type    : " + meaning
                for flagid, meaning, _ in self.__SECTION__HEADER_FLAGS__:
                    if (self.sections[item].get_flags() == flagid):
                        print "Section Flags   : " + meaning
    #
    #
    #
    def sbss(self):
        print "[BSS SECTION]"
        for item in self.sections:
            if (self.sections[item].get_fname() == '.bss'):
                print "Section Address : " + str(hex(self.sections[item].get_addr()))
                print "Section Offset  : " + str(hex(self.sections[item].get_offset()))
                print "Section Size    : " + str(hex(self.sections[item].get_size()))
                for flagid, meaning, _ in self.__SECTION__HEADER_INFO__:
                    if (self.sections[item].get_type() == flagid ):
                        print "Section Type    : " + meaning
                for flagid, meaning, _ in self.__SECTION__HEADER_FLAGS__:
                    if (self.sections[item].get_flags() == flagid):
                        print "Section Flags   : " + meaning
    #
    #
    #
    def diss(self, arch):
        print "[DISASSEMBLE]"

        if (arch == "__MIP__"):
            if (self.elf_header['e_class'] == 1):
                cs = Cs(CS_ARCH_MIPS, CS_MODE_MIP32)
            elif (self.elf_header['e_class'] == 2):
                cs = Cs(CS_ARCH_MIPS, CS_MODE_MIP64)

        if (arch == "__X86__"):
            if (self.elf_header['e_class'] == 1):
                cs = Cs(CS_ARCH_X86, CS_MODE_32)
            elif (self.elf_header['e_class'] == 2):
                cs = Cs(CS_ARCH_X86, CS_MODE_64)

        if (arch == "__ARM__"):
            if (self.elf_header['e_class'] == 1):
                cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            elif (sself.elf_header['e_class'] == 2):
                cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        cs.detail       = True
        start_address   = 0
        size_of_section = 0

        for item in self.sections:
            if (self.sections[item].get_fname() == '.text'):
                start_address    = self.sections[item].get_offset()
                size_of_section  = self.sections[item].get_size()
                addr             = self.sections[item].get_addr()
                print "Section Address : " + str(hex(self.sections[item].get_addr()))
                print "Section Offset  : " + str(hex(self.sections[item].get_offset()))
                print "Section Size    : " + str(hex(size_of_section))

        data = self.__data__[start_address:(start_address + size_of_section)]

        for i in cs.disasm(data, addr):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    #
    #
    #
    def __init__(self):
        # Define the private / local variables that we will use to create and parse the  ELFObject.
        self.__format__         = '<'
        self.__attrlt__         = []
        self.__offset__         = 0
        self.ELHEADER           = __FALSE__
        self.ELFILEHEADER       = __FALSE__
        self.ELFSECTIONHEADER   = __FALSE__
        self.sections_text      = __FALSE__
        self.sections_rdata     = __FALSE__
        self.sections_data      = __FALSE__
        self.sections_reloc     = __FALSE__
        self.sections_dis       = __FALSE__

        # Define the public variables that will comprise the ELFObject.
        self.elf_header         = {}
        self.elf_pheader        = []
        self.elf_sheader        = []
        self.sections           = {}
        self.sect               = {}
        self.e_phoff            = 0
        self.e_phnum            = 0
        self.e_shoff            = 0
#
#
#
