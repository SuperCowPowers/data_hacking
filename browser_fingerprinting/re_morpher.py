# Admittedly this is just hack-crap-tastic.. so happy to have someone
# contribute a better way to auto-generate regular expressions :)
import re
import difflib
import StringIO


class REMorpher():
    ''' RE Morpher modifies a regular expression so that it matches the input_seq '''
    def __init__(self):
        self.reset_re()
        self.op_map = {'literal': '%s', 'optional': '(%s)?', 'or': '(%s|%s)'}

    def reset_re(self):
        self.re_seq = []
        self.re_ops = []

    def add_sequence(self, input_seq):

        # First sequence?
        if not self.re_seq:
            self.re_seq = input_seq
            self.re_ops = ['literal'] * len(input_seq)

        # The RE might already match input_seq
        re_pattern = self.get_re_pattern()
        if re.match(re_pattern, ''.join(input_seq)):
            return

        # Nope, so make the smallest amount of changes so that it does match
        s = difflib.SequenceMatcher(None, self.re_seq, input_seq)
        orig_len = len(self.re_seq)
        for op_tuple in s.get_opcodes():

            # Handles to the opcodes
            op, re_start, re_end, in_start, in_end = op_tuple
            re_offset = len(self.re_seq) - orig_len
            re_start += re_offset
            re_end += re_offset

            # Do different modifications based on op type
            if op == 'replace':
                # Okay this logic needs to be fixed, right now just doing a psuedo 'or' with mulitple 'optional's.
                self.re_seq = self.re_seq[:re_start] + input_seq[in_start:in_end] + self.re_seq[re_end-1:]
                self.re_ops = self.re_ops[:re_start] + ['optional'] * (len(input_seq[in_start:in_end])+1) + self.re_ops[re_end-1:]
            if op == 'insert':
                self.re_seq = self.re_seq[:re_start] + input_seq[in_start:in_end] + self.re_seq[re_end:]
                self.re_ops = self.re_ops[:re_start] + ['optional'] * len(input_seq[in_start:in_end]) + self.re_ops[re_end:]

            if op == 'delete':
                for i in xrange(re_start, re_end):
                    self.re_ops[re_start:re_end] = ['optional'] * len(self.re_ops[re_start:re_end])


        # Sanity check the RE better match!
        re_pattern = self.get_re_pattern()
        if not re.match(re_pattern, ''.join(input_seq)):
            print 'Critical Error: RE did NOT match! Destroy the Universe!'
            print re_pattern
            print input_seq

    def get_re_pattern(self):
        output = StringIO.StringIO()
        _re_seq_prep = []
        for item, op in zip(self.re_seq, self.re_ops):
            buf = self.op_map[op] % item
            _re_seq_prep.append(buf)

        return ''.join(['^']+_re_seq_prep+['$'])

# Simple test of the re_morpher functionality
def _test():

    a = [u'HOST', u'CONNECTION', u'ACCEPT', u'USER_AGENT', u'ACCEPT-ENCODING', u'ACCEPT-LANGUAGE', u'IF-MODIFIED-SINCE']
    b = [u'HOST', u'CONNECTION', u'AUTHORIZATION', u'ACCEPT', u'USER_AGENT', u'ACCEPT-ENCODING', u'ACCEPT-LANGUAGE', u'IF-MODIFIED-SINCE']
    c = [u'HOST', u'ACCEPT', u'USER_AGENT', u'ACCEPT-ENCODING', u'ACCEPT-LANGUAGE', u'IF-MODIFIED-SINCE']
    d = [u'HOST', u'ACCEPT', u'BLAH-BLAH', u'ACCEPT-ENCODING', u'ACCEPT-LANGUAGE', u'IF-MODIFIED-SINCE']
    e = [u'HOST', u'ACCEPT', u'BLAH-BLAH', u'ACCEPT-ENCODING', u'ACCEPT-LANGUAGE', u'IF-MODIFIED-SINCE', 'AUTHORIZATION']

    my_re_morpher = REMorpher()

    my_re_morpher.add_sequence(a)
    print my_re_morpher.get_re_pattern()
    my_re_morpher.add_sequence(b)
    print my_re_morpher.get_re_pattern()
    my_re_morpher.add_sequence(c)
    print my_re_morpher.get_re_pattern()
    my_re_morpher.add_sequence(d)
    print my_re_morpher.get_re_pattern()


    # It should match all but 'e'
    match = [a, b, c, d]
    not_match = [e]
    re_pattern =  my_re_morpher.get_re_pattern()
    print '\n' * 3 + 'Testing Results:'
    for m in match:
        if re.match(re_pattern, ''.join(m)):
            print 'Good %s match' % m
        else:
            print 'FAIL: %s did not match' % m

    for m in not_match:
        if not re.match(re_pattern, ''.join(m)):
            print 'Good %s no-match' % m
        else:
            print 'FAIL: %s matched' % m


    # Additional testing
    foo =  [[u'CONNECTION', u'COOKIE', u'USER-AGENT', u'TRANSLATE', u'HOST'],
            [u'CONNECTION', u'COOKIE', u'USER-AGENT', u'TRANSLATE', u'HOST', u'AUTHORIZATION'],
            [u'CONNECTION', u'COOKIE', u'USER-AGENT', u'TRANSLATE', u'HOST', u'AUTHORIZATION'],
            [u'CONNECTION', u'COOKIE', u'USER-AGENT', u'DEPTH', u'TRANSLATE', u'CONTENT-LENGTH', u'HOST'],
            [u'CONNECTION', u'COOKIE', u'USER-AGENT', u'DEPTH', u'TRANSLATE', u'CONTENT-LENGTH', u'HOST', u'AUTHORIZATION'],
            [u'CONNECTION', u'COOKIE', u'USER-AGENT', u'DEPTH', u'TRANSLATE', u'CONTENT-LENGTH', u'HOST', u'AUTHORIZATION'],
            [u'CONNECTION', u'USER-AGENT', u'DEPTH', u'TRANSLATE', u'CONTENT-LENGTH', u'HOST', u'COOKIE'],
            [u'CONNECTION', u'USER-AGENT', u'DEPTH', u'TRANSLATE', u'CONTENT-LENGTH', u'HOST', u'COOKIE'],
            [u'CONNECTION', u'USER-AGENT', u'DEPTH', u'TRANSLATE', u'CONTENT-LENGTH', u'HOST', u'COOKIE'],
            [u'CONNECTION', u'USER-AGENT', u'DEPTH', u'TRANSLATE', u'CONTENT-LENGTH', u'HOST', u'COOKIE'],
            [u'CONNECTION', u'CONTENT-TYPE', u'USER-AGENT', u'X-VERMEER-CONTENT-TYPE', u'CONTENT-LENGTH', u'HOST', u'COOKIE'],
            [u'CONNECTION', u'USER-AGENT', u'DEPTH', u'TRANSLATE', u'CONTENT-LENGTH', u'HOST', u'COOKIE']]
    my_re_morpher.reset_re()
    for f in foo:
        my_re_morpher.add_sequence(f)
        print my_re_morpher.get_re_pattern()


if __name__ == "__main__":
    _test()