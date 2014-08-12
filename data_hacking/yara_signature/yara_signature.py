"""
Base class that holds the various properties of the Yara signature and is responsible
for assembling the pieces into a (hopefully) valid Yara signature
"""
import re

class InvalidTypeError(Exception):
    """ Simple error if we don't get the data type we expect """
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class YaraSignature:
    """
    This holds the signature pieces in a dictionary (__signature) and allows a few ways to add
    different types of data (stinrgs) and contitions for the strings.
    """
    __signature = {}

    def __init__(self, rulename="generatedSignature", meta=None, tag=""):
        """ Object init """
        if not isinstance(meta, dict):
            raise InvalidTypeError("Expected type: dict for variable meta, received type: %s" % type(meta))

        if len(tag) > 0:
            self.__signature['tag'] = tag

        self.__signature = {}
        self.__signature['_magic'] = []
        self.__signature['_name'] = self.__valid_rule_char(rulename)
        self.__signature['_meta'] = {}
        self.__signature['_regex'] = {}
        self.__signature['_named_hex_offset'] = []
        self.__signature['_named_string_offset'] = []
        self.__signature['_named_wide_string_offset'] = []
        self.__signature['_named_string'] = []
        self.__signature['_named_wide_string'] = []
        self.__signature['_named_hex'] = []
        self.__signature['_named_string_group'] = []
        self.__signature['_named_wide_string_group'] = []
        self.__signature['_named_hex_group'] = []
        self.__signature['_meta']['generator'] = 'This sweet yara sig generator!'
        if len(meta) > 0:
            self.__signature['_meta'].update(meta)

    @classmethod
    def __valid_rule_char(cls, rulename):
        """ make sure that there are only valid chars in the Yara rule name """
        rulename = re.sub('[^a-zA-z0-9_]', '_', rulename)
        if ord(rulename[0]) > 47 and ord(rulename[0]) < 58:
            rulename = rulename[1:]
        return rulename[:128]

    @classmethod
    def __cleanup_offset(cls, offset):
        """ some formatting inforced based on a couple of ways we can get offset information in, attempts to provide some flexibility """
        if str(offset).startswith('0x', 0, 2):
            offset = int(offset, 16)
        return str(offset)

    @classmethod
    def __cleanup_value(cls, value):
        """ makes sure hex values are prepended with 0x """
        if str(value).startswith('0x', 0, 2):
            value = str(value[2:])
        return str(value)

    def add_named_string(self, name, value):
        """
        Add a string type to a signature with a specific name. The name is used in the condition but also to provide conext
        to how/what the value is
        """
        ex = False
        for i in self.__signature['_named_string']:
            if i['value'] == value:
                ex = True
        if not ex:
            self.__signature['_named_string'].append({'name': str(name), 'value' : value})

    def add_named_hex(self, name, value, count=0):
        """
        Add a hex value type to a signature with a specific name. The name is used in the condition but also to provide conext
        to how/what the value is
        """
        ex = False
        for i in self.__signature['_named_hex']:
            if i['value'] == value:
                ex = True
        if not ex:
            self.__signature['_named_hex'].append({'name': str(name), 'value' : self.__cleanup_value(value), 'count' : count})

    def add_named_string_group(self, name, strings, wide=False):
        """
        Add a group of strings to a signature with a specific name.  The group is used for a bunch of related strings.
        The name is used in the condition but also to provide conext to how/what the value is.
        """
        if not (isinstance(strings, list) or isinstance(strings, set)):
            raise InvalidTypeError("Expected type: list or set, received type: %s" % type(strings))
        if len(strings) > 0:
            if wide:
                self.__signature['_named_wide_string_group'].append({'name': str(name), 'values' : strings})
            else:
                self.__signature['_named_string_group'].append({'name': str(name), 'values' : strings})

    def add_named_hex_group(self, name, strings):
        """
        Add a group of hex values to a signature with a specific name.  The group is used for a bunch of related hex values.
        The name is used in the condition but also to provide conext to how/what the value is.
        """
        if not (isinstance(strings, list) or isinstance(strings, set)):
            raise InvalidTypeError("Expected type: list or set, received type: %s" % type(strings))
        clean = []
        if len(strings) > 0:
            for i in strings:
                clean.append(self.__cleanup_value(i))
            self.__signature['_named_hex_group'].append({'name': str(name), 'values' : list(set(clean))})

    def set_const_pool(self, const_pool):
        """
        An abstraction for adding strings from constant pools (parsed from files).
        """
        if not (isinstance(const_pool, list) or isinstance(const_pool, set)):
            raise InvalidTypeError("Expected type: list or set, received type: %s" % type(const_pool))
        self.add_named_string_group("constpool", const_pool)

    def set_regex(self, strings):
        """
        Allows regexs in the strings and conditions sections of the signature, so everything gets setup correctly.
        """
        if not isinstance(strings, dict):
            raise InvalidTypeError("Expected type: dict, received type: %s" % type(strings))
        self.__signature['_regex'] = strings

    def add_named_string_offset(self, name, value, offset):
        """ Look for a specific string at a specific offset within the file """
        value = str(value)
        ex = False
        for i in self.__signature['_named_string_offset']:
            if i['value'] == value and i['offset'] == offset:
                ex = True
        if not ex:
            self.__signature['_named_string_offset'].append({'name' : name, 'value' : value, 'offset' : self.__cleanup_offset(offset)})

    def add_named_hex_offset(self, name, value, offset):
        """ Look for a specific hex value at a specific offset within the file """
        ex = False
        for i in self.__signature['_named_hex_offset']:
            if i['value'] == value and i['offset'] == offset:
                ex = True
        if not ex:
            self.__signature['_named_hex_offset'].append({'name' : name, 'value' : self.__cleanup_value(value), 'offset' : self.__cleanup_offset(offset)})

    def set_magic(self, value, offset):
        """ Shortcut for adding the value(s) for the magic number(s) of files """
        self.__signature['_magic'].append({'value' : self.__cleanup_value(value), 'offset' : self.__cleanup_offset(offset)})

    def set_file_size(self, size):
        """ Add the filesize to the rule """
        self.__signature['filesize'] = int(size)

    def generate_signature(self, filename=''):
        """
        Actually generate the signature. By setting filename it will write the signature out to the specified file.

        This function also returns the string representation of the signature as well. You can simply:
            print sig.generate_signature()
        to view the generated rule.
        """
        max_len = 1000
        condition = []
        variables = []
        fout = False
        sig_file = None
        sig_text = ""

        if len(filename) > 0:
            fout = True

        if fout:
            sig_file = open(filename, 'w')

        if 'tag' in self.__signature:
            if fout:
                sig_file.write("rule %s : %s\n{\n" % (self.__signature['_name'], self.__signature['tag']))
            sig_text = "rule %s : %s\n{\n" % (self.__signature['_name'], self.__signature['tag'])
        else:
            if fout:
                sig_file.write("rule %s\n{\n" % self.__signature['_name'])
            sig_text = "rule %s\n{\n" % self.__signature['_name']

        if len(self.__signature['_meta']) > 0:
            if fout:
                sig_file.write("meta:\n")
                for i in sorted(self.__signature['_meta'].items()):
                    sig_file.write("    %s = \"%s\"\n" % (i[0], i[1]))
                sig_file.write("\n")
            sig_text += "meta:\n"
            for i in sorted(self.__signature['_meta'].items()):
                sig_text += "    %s = \"%s\"\n" % (i[0], i[1])

        if '_named_string_group' in self.__signature and len(self.__signature['_named_string_group']) > 0:
            for i in self.__signature['_named_string_group']:
                if len(i['values']) > 0:
                    count = 0
                    for j in i['values']:
                        if len(j) < max_len:
                            count += 1
                            variables.append("$%s%s = \"%s\"" % (self.__valid_rule_char(i['name']), count, j))
                    condition.append("all of ($%s*)" % self.__valid_rule_char(i['name']))

        if '_named_wide_string_group' in self.__signature and len(self.__signature['_named_wide_string_group']) > 0:
            for i in self.__signature['_named_wide_string_group']:
                if len(i['values']) > 0:
                    count = 0
                    for j in i['values']:
                        if len(j) < max_len:
                            count += 1
                            variables.append("$%s%s = \"%s\" wide" % (self.__valid_rule_char(i['name']), count, j))
                    condition.append("all of ($%s*)" % self.__valid_rule_char(i['name']))

        if '_named_hex_group' in self.__signature and len(self.__signature['_named_hex_group']) > 0:
            for i in self.__signature['_named_hex_group']:
                if len(i['values']) > 0:
                    count = 0
                    for j in i['values']:
                        if len(j) < max_len:
                            count += 1
                            hexstring = []
                            for start in range(0, len(j), 2):
                                hexstring.append(j[start:start+2].zfill(2))
                            variables.append("$%s%s = { %s }" % (self.__valid_rule_char(i['name']), count, " ".join(hexstring)))
                    condition.append("all of ($%s*)" % self.__valid_rule_char(i['name']))

        if '_regex' in self.__signature and len(self.__signature['_regex']):
            for i in self.__signature['_regex']:
                variables.append("$%s = /%s/" % (self.__valid_rule_char(i), self.__signature['_regex'][i]))
                condition.append("$%s" % self.__valid_rule_char(i))

        if '_magic' in self.__signature and len(self.__signature['_magic']) > 0:
            m_count = 0
            for i in self.__signature['_magic']:
                hexstring = []
                for start in range(0, len(i['value']), 2):
                    hexstring.append(i['value'][start:start+2].zfill(2))
                variables.append("$magic%s = { %s }" % (m_count, " ".join(hexstring)))
                condition.append("$magic%s at %s" % (m_count, i['offset']))
                m_count += 1

        if '_named_string_offset' in self.__signature and len(self.__signature['_named_string_offset']) > 0:
            for i in self.__signature['_named_string_offset']:
                variables.append("$%s = \"%s\"" % (self.__valid_rule_char(i['name']), i['value']))
                condition.append("$%s at %s" % (self.__valid_rule_char(i['name']), i['offset']))

        if '_named_hex_offset' in self.__signature and len(self.__signature['_named_hex_offset']) > 0:
            for i in self.__signature['_named_hex_offset']:
                if len(i['value']) < max_len:
                    hexstring = []
                    for start in range(0, len(i['value']), 2):
                        hexstring.append(i['value'][start:start+2].zfill(2))
                    variables.append("$%s = { %s }" % (self.__valid_rule_char(i['name']), " ".join(hexstring)))
                    condition.append("$%s at %s" % (self.__valid_rule_char(i['name']), i['offset']))

        if '_named_string' in self.__signature and len(self.__signature['_named_string']) > 0:
            for i in self.__signature['_named_string']:
                if len(i['value']) < max_len:
                    variables.append("$%s = \"%s\"" % (self.__valid_rule_char(i['name']), i['value']))
                    if i['count'] != 0:
                        condition.append("#%s == %s" % (self.__valid_rule_char(i['name']), i['count']))
                    else:
                        condition.append("$%s" % self.__valid_rule_char(i['name']))

        if '_named_hex' in self.__signature and len(self.__signature['_named_hex']) > 0:
            for i in self.__signature['_named_hex']:
                if len(i['value']) < max_len:
                    hexstring = []
                    for start in range(0, len(i['value']), 2):
                        hexstring.append(i['value'][start:start+2].zfill(2))
                    variables.append("$%s = { %s }" % (self.__valid_rule_char(i['name']), " ".join(hexstring)))
                    if i['count'] != 0:
                        condition.append("#%s == %s" % (self.__valid_rule_char(i['name']), i['count']))
                    else:
                        condition.append("$%s" % self.__valid_rule_char(i['name']))

        if 'filesize' in self.__signature:
            condition.append("filesize == %s" % self.__signature['filesize'])

        if len(variables) > 0:
            if fout:
                sig_file.write("\nstrings:\n    " + "\n    ".join(variables) + "\n")
            sig_text += "\nstrings:\n    " + "\n    ".join(variables)

        if fout:
            sig_file.write("\ncondition:\n    " + " and\n    ".join(condition) + "\n}\n")
            sig_file.close()
        sig_text += "\ncondition:\n    " + " and\n    ".join(condition) + "\n}"

        return sig_text
