"""
An abstraction to create a Yara signature based on a provided PE file. This class
parses the file and extract the necessary values, as well as populates the signature
object.

This uses the yara_signature class to hold and create the signature.
"""
import pefile
import struct
import os
import string
import yara_signature
import hashlib

class YaraPEGenerator:
    """
    PE Yara Signature Object
    """
    __pe = None
    __sig = None
    __rulename = ""
    __filename = ""

    def __init__(self, filename, samplename='', meta={}, tag='', include_filename=False):
        """ Object Init """
        fname = os.path.split(filename)[1]
        self.__filename = filename
        if samplename == "":
            fhash = hashlib.sha256()
            afile = open(filename, 'rb')
            buf = afile.read(65536)
            while len(buf) > 0:
                fhash.update(buf)
                buf = afile.read(65536)
            self.__rulename = fhash.hexdigest()
        else:
            self.__rulename = samplename
        self.__sig = yara_signature.YaraSignature(rulename=self.__rulename, meta=meta, tag=tag)
        self.__pe = pefile.PE(filename)


    def __strings(self):
        """ Strings function to mimic the unix strings utility """
        with open(self.__filename, "rb") as f:
            result = ""
            for data in f.read():
                if data in string.printable:
                    result += data
                    continue
                if len(result) >= 8:
                    yield result.encode("hex")
                result = ""


    def add_section_names(self):
        """ Add the section names found in the PE file to the signature """
        section_names = []
        for section in self.__pe.sections:
            section_names.append(section.Name.encode("hex"))
        if len(list(set(section_names))) > 0:
            self.__sig.add_named_hex_group("section_name", list(set(section_names)))

    def add_section_info(self, values=[]):
        ''' Add information from the section headers to the signature '''

        if 'section 0 virtual size' in values and len(self.__pe.sections) > 0:
            value = struct.pack("<I", self.__pe.sections[0].Misc_VirtualSize).encode('hex')
            self.__sig.add_named_hex_offset("Section0VirtualAddress", value, int(self.__pe.DOS_HEADER.e_lfanew) + 0x100)

        if 'section 0 virtual address' in values and len(self.__pe.sections) > 0:
            value = struct.pack("<I", self.__pe.sections[0].VirtualAddress).encode('hex')
            self.__sig.add_named_hex_offset("Section0VirtualAddress", value, int(self.__pe.DOS_HEADER.e_lfanew) + 0x104)

        if 'section 1 virtual size' in values and len(self.__pe.sections) > 1:
            value = struct.pack("<I", self.__pe.sections[1].Misc_VirtualSize).encode('hex')
            self.__sig.add_named_hex_offset("Section0VirtualAddress", value, int(self.__pe.DOS_HEADER.e_lfanew) + 0x128)

        if 'section 1 virtual address' in values and len(self.__pe.sections) > 1:
            value = struct.pack("<I", self.__pe.sections[1].VirtualAddress).encode('hex')
            self.__sig.add_named_hex_offset("Section0VirtualAddress", value, int(self.__pe.DOS_HEADER.e_lfanew) + 0x12c)

        if 'section 2 virtual size' in values and len(self.__pe.sections) > 2:
            value = struct.pack("<I", self.__pe.sections[2].Misc_VirtualSize).encode('hex')
            self.__sig.add_named_hex_offset("Section0VirtualAddress", value, int(self.__pe.DOS_HEADER.e_lfanew) + 0x150)

        if 'section 2 virtual address' in values and len(self.__pe.sections) > 2:
            value = struct.pack("<I", self.__pe.sections[2].VirtualAddress).encode('hex')
            self.__sig.add_named_hex_offset("Section0VirtualAddress", value, int(self.__pe.DOS_HEADER.e_lfanew) + 0x154)

    def add_dos_header(self, values=[]):
        """ Add various attributes of the DOS header """
        self.__sig.set_magic(struct.pack("<H", self.__pe.DOS_HEADER.e_magic).encode("hex"), "0")
        if 'e_lfanew' in values:
            self.__sig.add_named_hex_offset("e_lfanew", hex(int(self.__pe.DOS_HEADER.e_lfanew)), "0x40")
        if 'PE' in values:
            self.__sig.add_named_hex_offset("PE", struct.pack("<L", self.__pe.NT_HEADERS.Signature).encode("hex"), hex(int(self.__pe.DOS_HEADER.e_lfanew)))
        if 'machine' in values:
            self.__sig.add_named_hex_offset("machine", struct.pack("<H", self.__pe.FILE_HEADER.Machine).encode("hex"), hex(int(self.__pe.DOS_HEADER.e_lfanew) + 4))

    def add_file_header(self, values=[]):
        """ Add all values of the file header, the values themselves are optional """
        #WORD           Machine
        #WORD           NumberOfSections
        #DWORD          TimeDateStamp
        #DWORD          PointerToSymbolTable
        #DWORD          NumberOfSymbols
        #WORD           SizeOfOptionalHeader
        #WORD           Characteristics

        if len(values) > 0:
            header = []
            header.append("????")
            header.append("????")
            header.append("????????")
            header.append("????????")
            header.append("????????")
            header.append("????")
            header.append("????")

            if 'machine' in values: header[0] = struct.pack("<H", self.__pe.FILE_HEADER.Machine).encode("hex")
            if 'number of sections' in values: header[1] = struct.pack("<H", self.__pe.FILE_HEADER.NumberOfSections).encode("hex")
            if 'compile date' in values: header[2] = struct.pack("<I", self.__pe.FILE_HEADER.TimeDateStamp).encode("hex")
            if 'pointer to symbol table' in values: header[3] = struct.pack("<I", self.__pe.FILE_HEADER.PointerToSymbolTable).encode("hex")
            if 'number of symbols' in values: header[4] = struct.pack("<I", self.__pe.FILE_HEADER.NumberOfSymbols).encode("hex")
            if 'size of optional header' in values: header[5] = struct.pack("<H", self.__pe.FILE_HEADER.SizeOfOptionalHeader).encode("hex")
            if 'characteristics' in values: header[6] = struct.pack("<H", self.__pe.FILE_HEADER.Characteristics).encode("hex")

            for i in range(len(header)):
                if '??' in header[-1]:
                    header.pop(-1)
                else:
                    break

            self.__sig.add_named_hex_offset("FileHeader", ''.join(header), int(self.__pe.DOS_HEADER.e_lfanew) + 4)

    def add_optional_header_pe32plus(self, values=[]):
        """ Add all values of optional header, the values themselves are optional """
        #WORD                 Magic;
        #BYTE                 MajorLinkerVersion;
        #BYTE                 MinorLinkerVersion;
        #DWORD                SizeOfCode;
        #DWORD                SizeOfInitializedData;
        #DWORD                SizeOfUninitializedData;
        #DWORD                AddressOfEntryPoint;
        #DWORD                BaseOfCode;
        #DWORD                ImageBase;
        #DWORD                SectionAlignment;
        #DWORD                FileAlignment;
        #WORD                 MajorOperatingSystemVersion;
        #WORD                 MinorOperatingSystemVersion;
        #WORD                 MajorImageVersion;
        #WORD                 MinorImageVersion;
        #WORD                 MajorSubsystemVersion;
        #WORD                 MinorSubsystemVersion;
        #DWORD                Win32VersionValue;
        #DWORD                SizeOfImage;
        #DWORD                SizeOfHeaders;
        #DWORD                CheckSum;
        #WORD                 Subsystem;
        #WORD                 DllCharacteristics;
        #DWORD                SizeOfStackReserve;
        #DWORD                SizeOfStackCommit;
        #DWORD                SizeOfHeapReserve;
        #DWORD                SizeOfHeapCommit;
        #DWORD                LoaderFlags;
        #DWORD                NumberOfRvaAndSizes;

        # 15 Data Directories follow with the below format
        #DWORD                VirtualAddress
        #DWORD                Size

        if len(values) > 0 and int(self.__pe.FILE_HEADER.SizeOfOptionalHeader) > 0:
            header = []
            header.append("????")
            header.append("??")
            header.append("??")
            for i in range(5):
                header.append("????????")
            header.append("????????????????")
            for i in range(2):
                header.append("????????")
            for i in range(6):
                header.append("????")
            for i in range(4):
                header.append("????????")
            for i in range(2):
                header.append("????")
            for i in range(4):
                header.append("????????????????")
            for i in range(2):
                header.append("????????")

            for i in range(15):
                header.append("????????")
                header.append("????????")

            if 'magic' in values: header[0] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.Magic).encode("hex")
            if 'major linker version' in values: header[1] = struct.pack("<B", self.__pe.OPTIONAL_HEADER.MajorLinkerVersion).encode("hex")
            if 'minor linker version' in values: header[2] = struct.pack("<B", self.__pe.OPTIONAL_HEADER.MinorLinkerVersion).encode("hex")
            if 'size of code' in values: header[3] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfCode).encode("hex")
            if 'size init data' in values: header[4] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfInitializedData).encode("hex")
            if 'size uninit data' in values: header[5] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfUninitializedData).encode("hex")
            if 'entry point address' in values: header[6] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.AddressOfEntryPoint).encode("hex")
            if 'base of code' in values: header[7] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.BaseOfCode).encode("hex")
            if 'image base' in values: header[8] = struct.pack("<Q", self.__pe.OPTIONAL_HEADER.ImageBase).encode("hex")
            if 'section alignment' in values: header[9] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SectionAlignment).encode("hex")
            if 'file alignment' in values: header[10] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.FileAlignment).encode("hex")
            if 'major operating system version' in values: header[11] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MajorOperatingSystemVersion).encode("hex")
            if 'minor operating system version' in values: header[12] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MinorOperatingSystemVersion).encode("hex")
            if 'major imageVersion' in values: header[13] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MajorImageVersion).encode("hex")
            if 'minor imageVersion' in values: header[14] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MinorImageVersion).encode("hex")
            if 'major subsystem version' in values: header[15] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MajorSubsystemVersion).encode("hex")
            if 'minor subsystem version' in values: header[16] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MinorSubsystemVersion).encode("hex")
            if 'win32 version value' in values: header[17] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.Win32VersionValue).encode("hex")
            if 'size of image' in values: header[18] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfImage).encode("hex")
            if 'size of headers' in values: header[19] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfHeaders).encode("hex")
            if 'checksum' in values: header[20] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.CheckSum).encode("hex")
            if 'subsystem' in values: header[21] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.Subsystem).encode("hex")
            if 'dll characteristics' in values: header[22] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.DllCharacteristics).encode("hex")
            if 'size of stack reserve' in values: header[23] = struct.pack("<Q", self.__pe.OPTIONAL_HEADER.SizeOfStackReserve).encode("hex")
            if 'size of stack commit' in values: header[24] = struct.pack("<Q", self.__pe.OPTIONAL_HEADER.SizeOfStackCommit).encode("hex")
            if 'size of heap reserve' in values: header[25] = struct.pack("<Q", self.__pe.OPTIONAL_HEADER.SizeOfHeapReserve).encode("hex")
            if 'size of heap commit' in values: header[26] = struct.pack("<Q", self.__pe.OPTIONAL_HEADER.SizeOfHeapCommit).encode("hex")
            if 'loader flags' in values: header[27] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.LoaderFlags).encode("hex")
            if 'number of rva and sizes' in values: header[28] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.NumberOfRvaAndSizes).encode("hex")
            if 'data dir export table rva' in values:
                header[29] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress).encode("hex")
            if 'data dir export table size' in values:
                header[30] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size).encode("hex")
            if 'data dir import table rva' in values:
                header[31] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress).encode("hex")
            if 'data dir import table size' in values:
                header[32] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size).encode("hex")
            if 'data dir resource table rva' in values:
                header[33] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress).encode("hex")
            if 'data dir resource table size' in values:
                header[34] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size).encode("hex")
            if 'data dir exception table rva' in values:
                header[35] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress).encode("hex")
            if 'data dir exception table size' in values:
                header[36] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size).encode("hex")
            if 'data dir certificate table rva' in values:
                header[37] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress).encode("hex")
            if 'data dir certificate table size' in values:
                header[38] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size).encode("hex")
            if 'data dir base relocation rva' in values:
                header[39] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress).encode("hex")
            if 'data dir base relocation size' in values:
                header[40] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size).encode("hex")
            if 'data dir debug rva' in values:
                header[41] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress).encode("hex")
            if 'data dir debug size' in values:
                header[42] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size).encode("hex")
            if 'data dir architecture rva' in values:
                header[43] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[7].VirtualAddress).encode("hex")
            if 'data dir architecture size' in values:
                header[44] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[7].Size).encode("hex")
            if 'data dir global ptr rva' in values:
                header[45] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[8].VirtualAddress).encode("hex")
            if 'data dir global ptr size' in values:
                header[46] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[8].Size).encode("hex")
            if 'data dir tls table rva' in values:
                header[47] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress).encode("hex")
            if 'data dir tls table size' in values:
                header[48] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size).encode("hex")
            if 'data dir load config table rva' in values:
                header[49] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[10].VirtualAddress).encode("hex")
            if 'data dir load config table size' in values:
                header[50] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[10].Size).encode("hex")
            if 'data dir bound import rva' in values:
                header[51] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].VirtualAddress).encode("hex")
            if 'data dir bound import size' in values:
                header[52] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].Size).encode("hex")
            if 'data dir import address table rva' in values:
                header[53] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress).encode("hex")
            if 'data dir import address table size' in values:
                header[54] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].Size).encode("hex")
            if 'data dir delay import descriptor rava' in values:
                header[55] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress).encode("hex")
            if 'data dir delay import descriptor size' in values:
                header[56] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size).encode("hex")
            if 'data dir clr runtime header rva' in values:
                header[57] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress).encode("hex")
            if 'data dir clr runtime header size' in values:
                header[58] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size).encode("hex")

            for i in range(len(header)):
                if '??' in header[-1]:
                    header.pop(-1)
                else:
                    break

            self.__sig.add_named_hex_offset("OptionalHeader", ''.join(header), int(self.__pe.DOS_HEADER.e_lfanew) + 24)

    def add_optional_header(self, values=[]):
        """ Add all values of optional header, the values themselves are optional """
        #WORD                 Magic;
        #BYTE                 MajorLinkerVersion;
        #BYTE                 MinorLinkerVersion;
        #DWORD                SizeOfCode;
        #DWORD                SizeOfInitializedData;
        #DWORD                SizeOfUninitializedData;
        #DWORD                AddressOfEntryPoint;
        #DWORD                BaseOfCode;
        #DWORD                BaseOfData - only in PE32;
        #DWORD                ImageBase;
        #DWORD                SectionAlignment;
        #DWORD                FileAlignment;
        #WORD                 MajorOperatingSystemVersion;
        #WORD                 MinorOperatingSystemVersion;
        #WORD                 MajorImageVersion;
        #WORD                 MinorImageVersion;
        #WORD                 MajorSubsystemVersion;
        #WORD                 MinorSubsystemVersion;
        #DWORD                Win32VersionValue;
        #DWORD                SizeOfImage;
        #DWORD                SizeOfHeaders;
        #DWORD                CheckSum;
        #WORD                 Subsystem;
        #WORD                 DllCharacteristics;
        #DWORD                SizeOfStackReserve;
        #DWORD                SizeOfStackCommit;
        #DWORD                SizeOfHeapReserve;
        #DWORD                SizeOfHeapCommit;
        #DWORD                LoaderFlags;
        #DWORD                NumberOfRvaAndSizes;

        # 15 Data Directories follow with the below format
        #DWORD                VirtualAddress
        #DWORD                Size

        if len(values) > 0 and int(self.__pe.FILE_HEADER.SizeOfOptionalHeader) > 0:
            header = []
            header.append("????")
            header.append("??")
            header.append("??")
            for i in range(9):
                header.append("????????")
            for i in range(6):
                header.append("????")
            for i in range(4):
                header.append("????????")
            for i in range(2):
                header.append("????")
            for i in range(6):
                header.append("????????")

            for i in range(15):
                header.append("????????")
                header.append("????????")

            if 'magic' in values: header[0] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.Magic).encode("hex")
            if 'major linker version' in values: header[1] = struct.pack("<B", self.__pe.OPTIONAL_HEADER.MajorLinkerVersion).encode("hex")
            if 'minor linker version' in values: header[2] = struct.pack("<B", self.__pe.OPTIONAL_HEADER.MinorLinkerVersion).encode("hex")
            if 'size of code' in values: header[3] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfCode).encode("hex")
            if 'size init data' in values: header[4] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfInitializedData).encode("hex")
            if 'size uninit data' in values: header[5] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfUninitializedData).encode("hex")
            if 'entry point address' in values: header[6] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.AddressOfEntryPoint).encode("hex")
            if 'base of code' in values: header[7] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.BaseOfCode).encode("hex")
            if 'base of data' in values: header[8] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.BaseOfData).encode("hex")
            if 'image base' in values: header[9] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.ImageBase).encode("hex")
            if 'section alignment' in values: header[10] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SectionAlignment).encode("hex")
            if 'file alignment' in values: header[11] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.FileAlignment).encode("hex")
            if 'major operating system version' in values: header[12] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MajorOperatingSystemVersion).encode("hex")
            if 'minor operating system version' in values: header[13] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MinorOperatingSystemVersion).encode("hex")
            if 'major imageVersion' in values: header[14] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MajorImageVersion).encode("hex")
            if 'minor imageVersion' in values: header[15] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MinorImageVersion).encode("hex")
            if 'major subsystem version' in values: header[16] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MajorSubsystemVersion).encode("hex")
            if 'minor subsystem version' in values: header[17] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.MinorSubsystemVersion).encode("hex")
            if 'win32 version value' in values: header[18] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.Win32VersionValue).encode("hex")
            if 'size of image' in values: header[19] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfImage).encode("hex")
            if 'size of headers' in values: header[20] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfHeaders).encode("hex")
            if 'checksum' in values: header[21] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.CheckSum).encode("hex")
            if 'subsystem' in values: header[22] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.Subsystem).encode("hex")
            if 'dll characteristics' in values: header[23] = struct.pack("<H", self.__pe.OPTIONAL_HEADER.DllCharacteristics).encode("hex")
            if 'size of stack reserve' in values: header[24] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfStackReserve).encode("hex")
            if 'size of stack commit' in values: header[25] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfStackCommit).encode("hex")
            if 'size of heap reserve' in values: header[26] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfHeapReserve).encode("hex")
            if 'size of heap commit' in values: header[27] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.SizeOfHeapCommit).encode("hex")
            if 'loader flags' in values: header[28] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.LoaderFlags).encode("hex")
            if 'number of rva and sizes' in values: header[29] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.NumberOfRvaAndSizes).encode("hex")
            if 'data dir export table rva' in values:
                header[30] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress).encode("hex")
            if 'data dir export table size' in values:
                header[31] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size).encode("hex")
            if 'data dir import table rva' in values:
                header[32] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress).encode("hex")
            if 'data dir import table size' in values:
                header[33] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size).encode("hex")
            if 'data dir resource table rva' in values:
                header[34] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress).encode("hex")
            if 'data dir resource table size' in values:
                header[35] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size).encode("hex")
            if 'data dir exception table rva' in values:
                header[36] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress).encode("hex")
            if 'data dir exception table size' in values:
                header[37] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size).encode("hex")
            if 'data dir certificate table rva' in values:
                header[38] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress).encode("hex")
            if 'data dir certificate table size' in values:
                header[39] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size).encode("hex")
            if 'data dir base relocation rva' in values:
                header[40] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress).encode("hex")
            if 'data dir base relocation size' in values:
                header[41] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size).encode("hex")
            if 'data dir debug rva' in values:
                header[42] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress).encode("hex")
            if 'data dir debug size' in values:
                header[43] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size).encode("hex")
            if 'data dir architecture rva' in values:
                header[44] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[7].VirtualAddress).encode("hex")
            if 'data dir architecture size' in values:
                header[45] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[7].Size).encode("hex")
            if 'data dir global ptr rva' in values:
                header[46] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[8].VirtualAddress).encode("hex")
            if 'data dir global ptr size' in values:
                header[47] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[8].Size).encode("hex")
            if 'data dir tls table rva' in values:
                header[48] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress).encode("hex")
            if 'data dir tls table size' in values:
                header[49] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size).encode("hex")
            if 'data dir load config table rva' in values:
                header[50] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[10].VirtualAddress).encode("hex")
            if 'data dir load config table size' in values:
                header[51] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[10].Size).encode("hex")
            if 'data dir bound import rva' in values:
                header[52] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].VirtualAddress).encode("hex")
            if 'data dir bound import size' in values:
                header[53] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].Size).encode("hex")
            if 'data dir import address table rva' in values:
                header[54] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress).encode("hex")
            if 'data dir import address table size' in values:
                header[55] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].Size).encode("hex")
            if 'data dir delay import descriptor rva' in values:
                header[56] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress).encode("hex")
            if 'data dir delay import descriptor size' in values:
                header[57] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size).encode("hex")
            if 'data dir clr runtime header rva' in values:
                header[58] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress).encode("hex")
            if 'data dir clr runtime header size' in values:
                header[59] = struct.pack("<I", self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size).encode("hex")

            for i in range(len(header)):
                if '??' in header[-1]:
                    header.pop(-1)
                else:
                    break

            self.__sig.add_named_hex_offset("OptionalHeader", ''.join(header), int(self.__pe.DOS_HEADER.e_lfanew) + 24)

    def add_optional_header_with_values(self, values={}):
        """ Add all values of optional header, the values themselves are optional """
        #WORD                 Magic;
        #BYTE                 MajorLinkerVersion;
        #BYTE                 MinorLinkerVersion;
        #DWORD                SizeOfCode;
        #DWORD                SizeOfInitializedData;
        #DWORD                SizeOfUninitializedData;
        #DWORD                AddressOfEntryPoint;
        #DWORD                BaseOfCode;
        #DWORD                BaseOfData - only in PE32;
        #DWORD                ImageBase;
        #DWORD                SectionAlignment;
        #DWORD                FileAlignment;
        #WORD                 MajorOperatingSystemVersion;
        #WORD                 MinorOperatingSystemVersion;
        #WORD                 MajorImageVersion;
        #WORD                 MinorImageVersion;
        #WORD                 MajorSubsystemVersion;
        #WORD                 MinorSubsystemVersion;
        #DWORD                Win32VersionValue;
        #DWORD                SizeOfImage;
        #DWORD                SizeOfHeaders;
        #DWORD                CheckSum;
        #WORD                 Subsystem;
        #WORD                 DllCharacteristics;
        #DWORD                SizeOfStackReserve;
        #DWORD                SizeOfStackCommit;
        #DWORD                SizeOfHeapReserve;
        #DWORD                SizeOfHeapCommit;
        #DWORD                LoaderFlags;
        #DWORD                NumberOfRvaAndSizes;

        # 15 Data Directories follow with the below format
        #DWORD                VirtualAddress
        #DWORD                Size

        if len(values) > 0:

            header = []
            header.append("????")
            header.append("??")
            header.append("??")
            for i in range(9):
                header.append("????????")
            for i in range(6):
                header.append("????")
            for i in range(4):
                header.append("????????")
            for i in range(2):
                header.append("????")
            for i in range(6):
                header.append("????????")

            for i in range(15):
                header.append("????????")
                header.append("????????")

            for key, value in values.iteritems():
                if key == 'magic': header[0] = value[0:4]
                if key == 'major linker version': header[1] = value[0:2]
                if key == 'minor linker version': header[2] = value[0:2]
                if key == 'size of code': header[3] = value[0:8]
                if key == 'size init data': header[4] = value[0:8]
                if key == 'size uninit data': header[5] = value[0:8]
                if key == 'entry point address': header[6] = value[0:8]
                if key == 'base of code': header[7] = value[0:8]
                if key == 'base of data': header[8] = value[0:8]
                if key == 'image base': header[9] = value[0:8]
                if key == 'section alignment': header[10] = value[0:8]
                if key == 'file alignment': header[11] = value[0:8]
                if key == 'major operating system version': header[12] = value[0:4]
                if key == 'minor operating system version': header[13] = value[0:4]
                if key == 'major imageVersion': header[14] = value[0:4]
                if key == 'minor imageVersion': header[15] = value[0:4]
                if key == 'major subsystem version': header[16] = value[0:4]
                if key == 'minor subsystem version': header[17] = value[0:4]
                if key == 'win32 version value': header[18] = value[0:8]
                if key == 'size of image': header[19] = value[0:8]
                if key == 'size of headers': header[20] = value[0:8]
                if key == 'checksum': header[21] = value[0:8]
                if key == 'subsystem': header[22] = value[0:4]
                if key == 'dll characteristics': header[23] = value[0:4]
                if key == 'size of stack reserve': header[24] = value[0:8]
                if key == 'size of stack commit': header[25] = value[0:8]
                if key == 'size of heap reserve': header[26] = value[0:8]
                if key == 'size of heap commit': header[27] = value[0:8]
                if key == 'loader flags': header[28] = value[0:8]
                if key == 'number of rva and sizes': header[29] = value[0:8]
                if key == 'data dir export table rva': header[30] = value[0:8]
                if key == 'data dir export table size': header[31] = value[0:8]
                if key == 'data dir import table rva': header[32] = value[0:8]
                if key == 'data dir import table size': header[33] = value[0:8]
                if key == 'data dir resource table rva': header[34] = value[0:8]
                if key == 'data dir resource table size': header[35] = value[0:8]
                if key == 'data dir exception table rva': header[36] = value[0:8]
                if key == 'data dir exception table size': header[37] = value[0:8]
                if key == 'data dir certificate table rva': header[38] = value[0:8]
                if key == 'data dir certificate table size': header[39] = value[0:8]
                if key == 'data dir base relocation rva': header[40] = value[0:8]
                if key == 'data dir base relocation size': header[41] = value[0:8]
                if key == 'data dir debug rva': header[42] = value[0:8]
                if key == 'data dir debug size': header[43] = value[0:8]
                if key == 'data dir architecture rva': header[44] = value[0:8]
                if key == 'data dir architecture size': header[45] = value[0:8]
                if key == 'data dir global ptr rva': header[46] = value[0:8]
                if key == 'data dir global ptr size': header[47] = value[0:8]
                if key == 'data dir tls table rva': header[48] = value[0:8]
                if key == 'data dir tls table size': header[49] = value[0:8]
                if key == 'data dir load config table rva': header[50] = value[0:8]
                if key == 'data dir load config table size': header[51] = value[0:8]
                if key == 'data dir bound import rva': header[52] = value[0:8]
                if key == 'data dir bound import size': header[53] = value[0:8]
                if key == 'data dir import address table rva': header[54] = value[0:8]
                if key == 'data dir import address table size': header[55] = value[0:8]
                if key == 'data dir delay import descriptor rva': header[56] = value[0:8]
                if key == 'data dir delay import descriptor size': header[57] = value[0:8]
                if key == 'data dir clr runtime header rva': header[58] = value[0:8]
                if key == 'data dir clr runtime header size': header[59] = value[0:8]

            for i in range(len(header)):
                if '??' in header[-1]:
                    header.pop(-1)
                else:
                    break

            self.__sig.add_named_hex_offset("OptionalHeader", ''.join(header), int(self.__pe.DOS_HEADER.e_lfanew) + 24)

    def add_resources(self):
        if hasattr(self.__pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            rva = self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress
            size = self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
            offset = get_offset_from_rva(rva)

    def add_file_info_strings(self):
        """ Add File information strings from the string table """
        strings = []
        if hasattr(self.__pe, 'FileInfo'):
            for entry in self.__pe.FileInfo:
                if hasattr(entry, 'StringTable'):
                    for st_entry in entry.StringTable:
                        for key, entry in st_entry.entries.items():
                            info = []
                            for i in key:
                                info.append(hex(ord(i))[2:].zfill(2))
                            strings.append('00'.join(info))
                            info = []
                            for i in entry:
                                info.append(hex(ord(i))[2:].zfill(2))
                            strings.append('00'.join(info))
            self.__sig.add_named_hex_group("file_info_string", strings)


    def add_imports(self):
        """ Extract and add imports to the yara signature """
        import_strings = []
        if hasattr(self.__pe, 'DIRECTORY_ENTRY_IMPORT'):
            for module in self.__pe.DIRECTORY_ENTRY_IMPORT:
                #h = []
                #for c in module.dll:
                #    h.append(hex(ord(c))[2:].zfill(2))
                #import_strings.append(''.join(h))
                #import_strings.append(module.dll.encode("hex"))
                import_strings.append(module.dll)
                for symbol in module.imports:
                    if symbol.import_by_ordinal is False:
                        import_strings.append(symbol.name)
            self.__sig.add_named_string_group("import_string", list(set(import_strings)))


    def add_exports(self):
        """ Extract and add exports to the yara sig """
        export_strings = []
        if hasattr(self.__pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in self.__pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.address is not None:
                    export_strings.append(export.name)
            self.__sig.add_named_string_group("export_string", list(set(export_strings)))


    def add_strings(self):
        """
        A _smart_ strings function, this will remove imports and exports from all strings found in the file
        that aren't in the exports, imports, or section names
        """
        strings = list(self.__strings())
        ignore_strings = []
        # Time to get all the strings to filter out
        # exports
        if hasattr(self.__pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in self.__pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.address is not None:
                    ignore_strings.append(export.name)
        # imports
        if hasattr(self.__pe, 'DIRECTORY_ENTRY_IMPORT'):
            for module in self.__pe.DIRECTORY_ENTRY_IMPORT:
                ignore_strings.append(module.dll)
                for symbol in module.imports:
                    if symbol.import_by_ordinal is False:
                        ignore_strings.append(symbol.name)
        # section names
        for section in self.__pe.sections:
            ignore_strings.append(section.Name.encode("hex"))
        # time to get the difference
        results = list(set(strings) - set(ignore_strings))
        if len(results) > 0:
            self.__sig.add_named_hex_group("misc_string", results)


    def get_signature(self, writesig=False, filename=''):
        """ Return the signature that was generated """
        if writesig:
            if len(filename) == 0:
                filename = self.__rulename + ".yara"
            return self.__sig.generate_signature(filename=filename)
        return self.__sig.generate_signature()

