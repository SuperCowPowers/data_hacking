''' This module handles the mechanics around easily pulling in Bro Log data
    The read_log method is a generator (in the python sense) for rows in a Bro log, 
    because of this, it's memory efficient and does not read the entire file into memory.
'''

import csv
import datetime
import optparse
import itertools


class BroLogReader():
    ''' This class implements a python based Bro Log Reader. '''

    def __init__(self):
        ''' Init for BroLogReader. '''
        self._delimiter = '\t'

    def read_log(self, logfile, max_rows=None):
        ''' The read_log method is a generator for rows in a Bro log. 
            Usage: rows = my_bro_reader.read_log(logfile) 
                   for row in rows:
                       do something with row
            Because this method returns a generator, it's memory
            efficient and does not read the entire file in at once.
        '''

        # First parse the header of the bro log
        bro_fptr, field_names, field_types = self._parse_bro_header(logfile)
        
        # Note: The parse_bro_header method has advanced us to the first
        #       real data row, so we can use the normal csv reader.
        reader = csv.DictReader(bro_fptr, fieldnames=field_names,
                                delimiter=self._delimiter, restval='BRO_STOP')
        for _row in itertools.islice(reader, 0, max_rows):
            values = self._cast_dict(_row)
            if (values):
                yield values

    def _parse_bro_header(self, logfile):
        ''' This method tries to parse the Bro log header section.
            Note: My googling is failing me on the documentation on the format,
                  so just making a lot of assumptions and skipping some shit.
            Assumption 1: The delimeter is a tab.
            Assumption 2: Types are either time, string, int or float
            Assumption 3: The header is always ends with #fields and #types as
                          the last two lines.
            
            Format example:
                #separator \x09
                #set_separator	,
                #empty_field	(empty)
                #unset_field	-
                #path	httpheader_recon
                #fields	ts	origin	useragent	header_events_json
                #types	time	string	string	string
        '''

        # Open the logfile
        _file = open(logfile, 'rb')

        # Skip until you find the #fields line
        _line = next(_file)
        while (not _line.startswith('#fields')):
            _line = next(_file)

        # Read in the field names
        _field_names = _line.strip().split(self._delimiter)[1:]

        # Read in the types
        _line = next(_file)
        _field_types = _line.strip().split(self._delimiter)[1:]

        # Return the header info
        return _file, _field_names, _field_types

    def _cast_dict(self, data_dict):
        ''' Internal method that makes sure any dictionary elements
            are properly cast into the correct types, instead of
            just treating everything like a string from the csv file
        ''' 
        for key, value in data_dict.iteritems():
            if (value == 'BRO_STOP'):
                return None
            data_dict[key] = self._cast_value(value)
        return data_dict

    def _cast_value(self, value):
        ''' Internal method that makes sure any dictionary elements
            are properly cast into the correct types, instead of
            just treating everything like a string from the csv file
        '''
        # First try time
        try:
            return datetime.datetime.fromtimestamp(float(value))

        # Next try a set of primitive types
        except ValueError: 
            tests = (int, float, str)
            for test in tests:
                try:
                    return test(value)
                except ValueError:
                    continue
            return value


if __name__ == '__main__':

    # Handle command-line arguments
    PARSER = optparse.OptionParser()    
    PARSER.add_option('--logfile', default=None, help='Logfile to read from.  Default: %default')
    (OPTIONS, ARGUMENTS) = PARSER.parse_args()
    print OPTIONS, ARGUMENTS

    # Create a BRO log file reader and pull from the logfile
    BRO_LOG = BroLogReader()
    RECORDS = BRO_LOG.read_log(OPTIONS.logfile, max_rows=10)
    for row in RECORDS:
        print row