"""
An abstraction to create a Yara signature based on a provided Mach-O file. This class
parses the file and extract the necessary values, as well as populates the signature
object.

This uses the yara_signature class to hold and create the signature.
"""
import macholib.MachO
import struct
import os
import re
import string
import hashlib
import yara_signature

class YaraMachoGenerator:
    """
    Mach-O Yara signature object
    """
    __mm = None
    __sig = None
    __const_strings = []
    __symbol_table_strings = []
    __rulename = ""
    __dyld_count = 0

    def __init__(self, filename, samplename='', meta=None, tag='', include_filename=False):
        """ Object init """
        fname = os.path.split(filename)[1]

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
        self.__mm = macholib.MachO.MachO(filename)
        self.__dyld_count = 0


    @classmethod
    def __byte_order(cls, header):
        """ Check to see if the part of the file that's being parsed is big or little endian based on header value """
        if header.MH_MAGIC in [0xcffaedfe, 0xcefaedfe]:
            return '<'
        return '>'

    def add_segment_64(self, symbols=[]):
        """ Add an LC_SEGMENT_64 command to the signature """
        # Skipping maxprot and beyond for now. Need to figure out how to account for vm_prot_t data types
        #uint32_t    cmd;        /* LC_SEGMENT */
        #uint32_t    cmdsize;    /* includes sizeof section structs */
        #char        segname[16];    /* segment name */
        #uint64_t    vmaddr;     /* memory address of this segment */
        #uint64_t    vmsize;     /* memory size of this segment */
        #uint64_t    fileoff;    /* file offset of this segment */
        #uint64_t    filesize;   /* amount to map from the file */
        #vm_prot_t   maxprot;    /* maximum VM protection */
        #vm_prot_t   initprot;   /* initial VM protection */
        #uint32_t    nsects;     /* number of sections in segment */
        #uint32_t    flags;      /* flags */
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_info = cmd[1]
                try:
                    if load_cmd.get_cmd_name() == 'LC_SEGMENT_64':
                        segment = []
                        segment.append("???????????????????????????????")
                        for i in range(5):
                            segment.append("????????????????")

                        cmd_bytes = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmd).encode('hex')
                        cmd_size = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmdsize).encode('hex')
                        if 'vmaddr' in symbols: segment[0] = struct.pack(self.__byte_order(header) + 'Q', cmd_info.describe()['vmaddr']).encode('hex')
                        if 'vmsize' in symbols: segment[1] = struct.pack(self.__byte_order(header) + 'Q', cmd_info.describe()['vmsize']).encode('hex')
                        if 'fileoff' in symbols: segment[2] = struct.pack(self.__byte_order(header) + 'Q', cmd_info.describe()['fileoff']).encode('hex')
                        if 'filesize' in symbols: segment[3] = struct.pack(self.__byte_order(header) + 'Q', cmd_info.describe()['filesize']).encode('hex')
                        if len(symbols) > 0:
                            for i in range(len(segment)):
                                if '??' in segment[-1]:
                                    segment.pop(-1)
                                else:
                                    break
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size + ''.join(segment))
                        else:
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size)
                        self.__dyld_count += 1
                except Exception as e:
                    print "EXCEPTION: %s" % str(e)


    def add_segment(self, symbols=[]):
        """ Add an LC_SEGMENT command to the signature """
        # Skipping maxprot and beyond for now. Need to figure out how to account for vm_prot_t data types
        #uint32_t    cmd;        /* LC_SEGMENT */
        #uint32_t    cmdsize;    /* includes sizeof section structs */
        #char        segname[16];    /* segment name */
        #uint32_t    vmaddr;     /* memory address of this segment */
        #uint32_t    vmsize;     /* memory size of this segment */
        #uint32_t    fileoff;    /* file offset of this segment */
        #uint32_t    filesize;   /* amount to map from the file */
        #vm_prot_t   maxprot;    /* maximum VM protection */
        #vm_prot_t   initprot;   /* initial VM protection */
        #uint32_t    nsects;     /* number of sections in segment */
        #uint32_t    flags;      /* flags */
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_info = cmd[1]
                try:
                    if load_cmd.get_cmd_name() == 'LC_SEGMENT':
                        segment = []
                        segment.append("???????????????????????????????")
                        for i in range(5):
                            segment.append("????????")

                        cmd_bytes = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmd).encode('hex')
                        cmd_size = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmdsize).encode('hex')
                        if 'vmaddr' in symbols: segment[0] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['vmaddr']).encode('hex')
                        if 'vmsize' in symbols: segment[1] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['vmsize']).encode('hex')
                        if 'fileoff' in symbols: segment[2] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['fileoff']).encode('hex')
                        if 'filesize' in symbols: segment[3] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['filesize']).encode('hex')
                        if len(symbols) > 0:
                            for i in range(len(segment)):
                                if '??' in segment[-1]:
                                    segment.pop(-1)
                                else:
                                    break
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size + ''.join(segment))
                        else:
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size)
                        self.__dyld_count += 1
                except Exception as e:
                    print "EXCEPTION: %s" % str(e)


    def add_symtab(self, symbols=[]):
        """ Add LC_SYMTAB command to signature """
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_info = cmd[1]
                try:
                    if load_cmd.get_cmd_name() == 'LC_SYMTAB':
                        symtab = []
                        for i in range(4):
                            symtab.append("????????")

                        cmd_bytes = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmd).encode('hex')
                        cmd_size = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmdsize).encode('hex')
                        if 'symoff' in symbols: symtab[0] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['symoff']).encode('hex')
                        if 'nsyms' in symbols: symtab[1] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nsyms']).encode('hex')
                        if 'stroff' in symbols: symtab[2] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['stroff']).encode('hex')
                        if 'strsize' in symbols: symtab[3] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['strsize']).encode('hex')
                        if len(symbols) > 0:
                            for i in range(len(symtab)):
                                if '??' in symtab[-1]:
                                    symtab.pop(-1)
                                else:
                                    break
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size + ''.join(symtab))
                        else:
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size)
                        self.__dyld_count += 1
                except Exception as e:
                    print "EXCEPTION: %s" % str(e)


    def add_dyld_info(self, symbols=[]):
        """ Add LC_DYLD_INFO command to signature """
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_info = cmd[1]
                try:
                    if load_cmd.get_cmd_name() in ('LC_DYLD_INFO_ONLY', 'LC_DYLD_INFO'):
                        dyld_info = []
                        for i in range(10):
                            dyld_info.append("????????")

                        cmd_bytes = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmd).encode('hex')
                        cmd_size = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmdsize).encode('hex')
                        if 'rebase_off' in symbols: dyld_info[0] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['rebase_off']).encode('hex')
                        if 'rebase_size' in symbols: dyld_info[1] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['rebase_size']).encode('hex')
                        if 'bind_off' in symbols: dyld_info[2] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['bind_off']).encode('hex')
                        if 'bind_size' in symbols: dyld_info[3] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['bind_size']).encode('hex')
                        if 'weak_bind_off' in symbols: dyld_info[4] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['weak_bind_off']).encode('hex')
                        if 'weak_bind_size' in symbols: dyld_info[5] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['weak_bind_size']).encode('hex')
                        if 'lazy_bind_off' in symbols: dyld_info[6] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['lazy_bind_off']).encode('hex')
                        if 'lazy_bind_size' in symbols: dyld_info[7] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['lazy_bind_size']).encode('hex')
                        if 'export_off' in symbols: dyld_info[8] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['export_off']).encode('hex')
                        if 'export_size' in symbols: dyld_info[9] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['export_size']).encode('hex')
                        if len(symbols) > 0:
                            for i in range(len(dyld_info)):
                                if '??' in dyld_info[-1]:
                                    dyld_info.pop(-1)
                                else:
                                    break
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size + ''.join(dyld_info))
                        else:
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size)
                        self.__dyld_count += 1
                except Exception as e:
                    print str(e)


    def add_dysymtab(self, symbols=[]):
        """ Add LC_DYSYMTAB command to signature """
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_info = cmd[1]
                try:
                    if load_cmd.get_cmd_name() == 'LC_DYSYMTAB':
                        dysymtab = []
                        for i in range(18):
                            dysymtab.append("????????")

                        cmd_bytes = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmd).encode('hex')
                        cmd_size = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmdsize).encode('hex')
                        if 'ilocalsym' in symbols: dysymtab[0] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['ilocalsym']).encode('hex')
                        if 'nlocalsym' in symbols: dysymtab[1] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nlocalsym']).encode('hex')
                        if 'iextdefsym' in symbols: dysymtab[2] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['iextdefsym']).encode('hex')
                        if 'nextdefsym' in symbols: dysymtab[3] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nextdefsym']).encode('hex')
                        if 'iundefsym' in symbols: dysymtab[4] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['iundefsym']).encode('hex')
                        if 'nundefsym' in symbols: dysymtab[5] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nundefsym']).encode('hex')
                        if 'tocoff' in symbols: dysymtab[6] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['tocoff']).encode('hex')
                        if 'ntoc' in symbols: dysymtab[7] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['ntoc']).encode('hex')
                        if 'modtaboff' in symbols: dysymtab[8] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['modtaboff']).encode('hex')
                        if 'nmodtab' in symbols: dysymtab[9] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nmodtab']).encode('hex')
                        if 'extrefsymoff' in symbols: dysymtab[10] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['extrefsymoff']).encode('hex')
                        if 'nextrefsyms' in symbols: dysymtab[11] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nextrefsyms']).encode('hex')
                        if 'indirectsymoff' in symbols: dysymtab[12] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['indirectsymoff']).encode('hex')
                        if 'nindirectsyms' in symbols: dysymtab[13] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nindirectsyms']).encode('hex')
                        if 'extreloff' in symbols: dysymtab[14] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['extreloff']).encode('hex')
                        if 'nextrel' in symbols: dysymtab[15] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nextrel']).encode('hex')
                        if 'nlocrel' in symbols: dysymtab[16] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['nlocrel']).encode('hex')
                        if 'locreloff' in symbols: dysymtab[17] = struct.pack(self.__byte_order(header) + 'I', cmd_info.describe()['locreloff']).encode('hex')
                        if len(symbols) > 0:
                            for i in range(len(dysymtab)):
                                if '??' in dysymtab[-1]:
                                    dysymtab.pop(-1)
                                else:
                                    break
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size + ''.join(dysymtab))
                        else:
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size)
                        self.__dyld_count += 1
                except Exception as e:
                    print str(e)


    def add_lc(self, lc_name):
        """ Add the presense of a Load Command to signature. extra bytes are added to allow for a longer byte match while ignoring size """
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                try:
                    if load_cmd.get_cmd_name() == lc_name:
                        cmd_bytes = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmd).encode('hex')
                        # including cmd_size is key to having more accurate yara sigs, but it'll cause files to be missed currently :(
                        #self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + cmd_size)
                        #cmd_size = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmdsize).encode('hex')
                        # This might be the shittiest heuristic ever, but it should work on all x86 stuff
                        self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + "??000000")
                        self.__dyld_count += 1
                except Exception as e:
                    print str(e)


    def add_lc_count(self, lc_name, count, size=-1):
        """
        The same as add_lc but it add the number of the LC to the signature for use in the condition.
        size is used to specify the command size
        count is used to specifiy the number of the specified lc_name to be used in the condition
        """
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                try:
                    if load_cmd.get_cmd_name() == lc_name:
                        cmd_bytes = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmd).encode('hex')
                        if size == -1:
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + "??000000", count=count)
                        else:
                            self.__sig.add_named_hex(load_cmd.get_cmd_name() + "_" + str(self.__dyld_count), cmd_bytes + struct.pack(self.__byte_order(header) + 'I', size).encode('hex'), count=count)
                        self.__dyld_count += 1
                        break
                except Exception as e:
                    print str(e)


    def add_headers(self):
        """ Add the header/magic number information to signature """
        if self.__mm.fat:
            self.__sig.set_magic('cafebabe', 0)

        for header in self.__mm.headers:
            self.__sig.set_magic(hex(int(header.MH_MAGIC)), hex(int(header.offset)))
            arch = 0
            if header.MH_MAGIC in [0xcffaedfe, 0xcefaedfe]:
                arch = 86
            for hval in header.header._describe():
                value = 0
                if hval[0] == 'cputype':
                    offset = 4
                if hval[0] == 'cpusubtype':
                    offset = 8
                if hval[0] == 'filetype':
                    offset = 12

                if hval[0] in ['cputype', 'cpusubtype', 'filetype']:
                    if arch == 86:
                        value = struct.pack('<I', hval[1]).encode('hex')
                    else:
                        value = struct.pack('>I', hval[1]).encode('hex')
                    self.__sig.add_named_hex_offset(hval[0]+'_'+hex(int(header.offset) + offset), value, hex(int(header.offset) + offset))


    def add_symbol_table_strings(self):
        """ Add strings found in the symbol table to the signature """
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_data = cmd[2]
                try:
                    if load_cmd.get_cmd_name() == 'LC_SYMTAB':
                        self.__symbol_table_strings.extend(cmd_data.strip('\x00').split('\x00'))
                except Exception as e:
                    print str(e)
        self.__symbol_table_strings = [x for x in self.__symbol_table_strings if not re.search(r"[\s\"\\]", x) and len(x) > 5  and all(c in string.printable for c in x)]
        self.__sig.add_named_string_group("symboltable", set(self.__symbol_table_strings))


    def add_constant_pool(self):
        """ Add strings found in the constant pool to signature """
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_data = cmd[2]
                try:
                    if load_cmd.get_cmd_name() in ('LC_SEGMENT', 'LC_SEGMENT_64'):
                        for section_data in cmd_data:
                            sd_info = section_data.describe()
                            if hasattr(section_data, 'section_data'):
                                if 'flags' in sd_info and 'type' in sd_info['flags'] and sd_info['flags']['type'] == 'S_CSTRING_LITERALS':
                                    self.__const_strings.extend(section_data.section_data.split('\0'))
                except Exception as e:
                    print str(e)
        self.__const_strings = [x for x in self.__const_strings if not re.search(r"[\s\"\\]", x) and len(x) > 5  and all(c in string.printable for c in x)]
        self.__sig.set_const_pool(set(self.__const_strings))


    def add_section_names(self):
        """ Add the section names to the signature """
        # Looks for all the UNIQUE combos of sectname segment name that can be found in the binary
        # no offsets :( but at least we can look for a really long string to keep things accurate
        sections = {}
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_data = cmd[2]
                try:
                    if load_cmd.get_cmd_name() in ('LC_SEGMENT', 'LC_SEGMENT_64'):
                        for section_data in cmd_data:
                            sd_info = section_data.describe()
                            if hasattr(section_data, 'section_data'):
                                # Might need to care about byte order here
                                sectname = sd_info['sectname']
                                segname = sd_info['segname']
                                nulls = "00" * (16 - len(sectname))
                                data = sectname.encode("hex") + nulls + segname.encode("hex")
                                sections[sectname+"_"+segname] = data
                except Exception as e:
                    print str(e)
        for sec in sections:
            self.__sig.add_named_hex(sec, sections[sec])


    # ex hex data: 24 00 00 00 10 00 00 00 00 07 0a 00 - 10.7.0
    # sig:         24 00 00 00 10 00 00 00 ?? 07 0a 00 - 10.7. (all 10.7 binaries)
    def add_version_min_macosx(self):
        """ Add the LC for min Mac OS X version including major and minor version to signature """
        for header in self.__mm.headers:
            for cmd in header.commands:
                load_cmd = cmd[0]
                try:
                    if load_cmd.get_cmd_name() in ['LC_VERSION_MIN_IPHONEOS', 'LC_VERSION_MIN_MACOSX']:
                        cmd_bytes = struct.pack(self.__byte_order(header) + 'I', load_cmd.cmd).encode('hex')
                        versions = cmd[1].describe()['version'].split('.')[:2]
                        maxv = struct.pack(self.__byte_order(header) + 'H', int(versions[0])).encode('hex')
                        minorv = struct.pack(self.__byte_order(header) + 'B', int(versions[1])).encode('hex')
                        self.__sig.add_named_hex('LC_VERSION_MIN_MACOSX', cmd_bytes + "10000000??" + minorv + maxv + "00")
                except Exception as e:
                    print str(e)


    def get_signature(self, writesig=False, filename=''):
        """
        Retreive the generated signature.
        writesig specifies if the signature should be written to disk.
        filename is the filename to use when writesig is present.
        """
        if writesig:
            if len(filename) == 0:
                filename = self.__rulename + ".yara"
            return self.__sig.generate_signature(filename=filename)
        return self.__sig.generate_signature()
