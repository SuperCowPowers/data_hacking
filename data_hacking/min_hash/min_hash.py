''' This module computes similarities between samples.
    To avoid O(N**2) running time we're using a banded
    min hash technique to reduce the number of comparisions when
    a new sample is encountered.
    * http://en.wikipedia.org/wiki/Jaccard_index
    * http://en.wikipedia.org/wiki/MinHash
    * http://infolab.stanford.edu/~ullman/mmds/ch3.pdf

'''

import os, sys
import pickle
import random
import hashlib
import collections
from struct import unpack

class MinHash():
    ''' This class implements MinHash (en.wikipedia.org/wiki/Minhash) 
        for sparse datasets. It also does banded LSH 'Locality Sensitive Hashing'
        so that only candidates with a high probability of being similar are
        returned by getCandidatePairs().
    '''    

    def __init__(self, num_hashes=40, lsh_bands=10, lsh_rows=4, load_models=None, drop_duplicates=False):
        ''' Init for MinHash '''

        # Minhash signatures, hashing and banding parameters
        self._minhash_sigs = {}
        self._num_hashes = num_hashes
        self._lsh_bands = lsh_bands
        self._lsh_rows = lsh_rows
        self._hash_salt = []
        for i in xrange(num_hashes):
            self._hash_salt.append(str(int(random.random()*100)))

        # Storage for candidate buckets
        def _min_hash_hash_bucket():
            ''' Defining a hash bucket 'callable' for the candidate buckets '''
            return collections.defaultdict(list)        
        self._candidate_buckets = collections.defaultdict(_min_hash_hash_bucket)

        # Set of All 2 All, Candidate Pairs
        self._all_candidate_pairs = set()

        # Hash storage for instances (used for duplicate detection)
        self._instances_hashes = set()
        self._drop_duplicates = drop_duplicates

        # Existing model load?
        if (load_models):
            # Salt has to be reloaded, everything else is optional
            self._hash_salt = self._load_model_from_disk("min_hash_salt", "models")
            if ("buckets" in load_models):
                self._candidate_buckets = self._load_model_from_disk("min_hash_candidate_buckets", "models")
            if ("pairs" in load_models):
                self._all_candidate_pairs = self._load_model_from_disk("min_hash_all_candidate_pairs", "models")
            if ("minhash" in load_models):
                self._minhash_sigs = self._load_model_from_disk("min_hash_minhash_sigs", "models")                

    def reset(self):
        ''' Reset for MinHash '''

        # Reset Minhash signatures
        self._minhash_sigs = {}

        # Rest Storage for candidate buckets      
        self._candidate_buckets = collections.defaultdict(_min_hash_hash_bucket)

        # Reset All 2 All, Candidate Pairs
        self._all_candidate_pairs = set()

        # Rest Hash storage for instances (used for duplicate detection)
        self._instances_hashes = set()

    def add_instance(self, name, attribute_list):
        ''' Add an instance to the min hash model '''

        # Make sure the attributes are coming in the right way
        if not isinstance(attribute_list, list):
            print "Min_hash.addinstance() : Attributes must be in a list!"
            print type(attribute_list)
            sys.exit(1)
        if not all(isinstance(x,str) for x in attribute_list):
            print "Min_hash.addinstance() : All attributes must be of str type!"
            print attribute_list
            sys.exit(1)        

        # Drop duplicates?
        if (self._drop_duplicates):
            instance_hash = self._hash_list_as_string(attribute_list)
            if (instance_hash in self._instances_hashes):
                return
            else:
                self._instances_hashes.add(instance_hash)

        # Compute the min hash signature and add to candidate buckets
        self._minhash_sigs[name] = self.compute_minhash_sig(attribute_list)
        self._add_to_candidate_buckets(name, self._minhash_sigs[name])

    def compute_minhash_sig(self, attribute_list):
        ''' Compute the min hash signature '''

        minhash_sig = []
        for salt in self._hash_salt:
            minhash_sig.append(self._minhash_hash(salt, attribute_list))
        return minhash_sig

    def candidate_query(self, attribute_list):
        
        # Compute the min hash signature and build a candidate match list
        minhash_sig = self.compute_minhash_sig(attribute_list)

        # Signature width
        bands = self._lsh_bands
        rows = self._lsh_rows
        sig_width = bands*rows

        # Getting matches from Hash Buckets
        _candidate_matches = set()
        for y_index in xrange(0, sig_width, rows):
            candidate_list = self._candidate_buckets[y_index][self._hash_list_as_string(minhash_sig[y_index:y_index+rows])]
            for match in candidate_list:
                _candidate_matches.add(match)

        # Return just the matches
        return _candidate_matches

    def compute_all_candidate_matches(self):
        ''' Compute band based candidate list for all instances in the model '''

        print "\tComputing All to All Candidates Matches..."
        self._all_to_all_matches()

    def get_candidate_pairs(self):
        ''' Get the candidate pairs for all instances in the model '''
        return self._all_candidate_pairs

    def save_model_to_disk(self):
        ''' Save all the minhash internal models to disk '''

        self._save_model_to_disk("min_hash_salt", self._hash_salt, "models")
        self._save_model_to_disk("min_hash_candidate_buckets", self._candidate_buckets, "models")
        self._save_model_to_disk("min_hash_all_candidate_pairs", self._all_candidate_pairs, "models")
        self._save_model_to_disk("min_hash_minhash_sigs", self._minhash_sigs, "models")

    # This function needs to be highly optimized
    # Compute min hash on a list of items
    def _minhash_slow(self, salt, v_list):
        ''' Compute a hash value for the list of values, the 'salt' is a random permutation factor '''
        minhash = "ffffffffffffffffffffffffffffffff"
        for value in v_list:
            h_value = hashlib.md5(value+salt).hexdigest()
            if (h_value < minhash):
                minhash = h_value
        return minhash

    def _minhash_hash(self, salt, v_list):
        ''' Compute a hash value for the list of values, the 'salt' is a random permutation factor '''
        minhash = sys.maxint
        for value in v_list:
            h_value = unpack("<IIII", hashlib.md5(value+salt).digest())[0]
            if (h_value < minhash):
                minhash = h_value
        return minhash

    # Hash a list of items
    def _hash_list_as_string(self, x_list):
        ''' Compute a hash value for the list of values by turning the list into a string first '''
        return hashlib.md5(str(x_list)).hexdigest()

    def _add_to_candidate_buckets(self, name, minhash_sig):
        ''' Add this minhash signature to the candidate buckets '''

        # Signature width
        bands = self._lsh_bands
        rows = self._lsh_rows
        sig_width = bands*rows

        for y_index in xrange(0, sig_width, rows):

            # Fixme: not totally sure what to do as these buckets get really big
            hash_key = self._hash_list_as_string(minhash_sig[y_index:y_index+rows])
            self._candidate_buckets[y_index][hash_key].append(name)

    def _all_to_all_matches(self):
        ''' Getting the candidate matches for all instances in the model '''

        # Linear pass to collapse candidate pairs (the buckets will have repeats)
        print "\t\tCollapsing Candidate Pairs..."
        for _key, subdict in self._candidate_buckets.iteritems():
            for __key, candidate_list in subdict.iteritems():

                # Sanity check
                if (len(candidate_list) > 1000):
                    print "Hashing function issue, key: (%s,%s) has %d items in it" % (_key, __key, len(candidate_list))
                    print "LIMITED IT to 1000"
                    candidate_list = candidate_list[:1000]

                for source in candidate_list:
                    for target in candidate_list:
                        if (source != target):
                            if (source < target):
                                self._all_candidate_pairs.add((source, target))
                            else:
                                self._all_candidate_pairs.add((target, source))

    def _save_model_to_disk(self, name, model, model_dir):
        ''' Save a particular model to disk '''

        # First serialized the model
        serialized_model = pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL)

        # Model directory + model name
        model_path = os.path.join(model_dir, name+".model")

        # Now store it to disk
        print "Storing Serialized Model to Disk (%s:%.2fMeg)" % (name, len(serialized_model)/1024.0/1024.0)
        open(model_path,"wb").write(serialized_model)

    def _load_model_from_disk(self, name, model_dir):
        ''' Load a particular model from disk '''

        # Model directory is relative to this file
        model_path = os.path.join(model_dir, name+".model")

        # Put a try/except around the model load in case it fails
        try:
            model = pickle.loads(open(model_path,'rb').read())
        except:
            print "Could not load model: %s from directory %s!" % (name, model_path)
            sys.exit(1)

        return model

# Simple test of the min_hash functionality
def _test():
    
    import pprint

    my_min = MinHash(num_hashes=40, lsh_bands=20, lsh_rows=2, drop_duplicates=True)
    my_min.add_instance(1, ['a','b','c','d'])
    my_min.add_instance(2, ['a','b','d'])
    my_min.add_instance(3, ['a','b','e','d'])
    my_min.add_instance(4, ['w','x','y','z'])
    my_min.add_instance(5, ['x','y','z'])
    my_min.add_instance(6, ['w','x','q','z','y'])
    my_min.add_instance(7, ['r','s','t'])
    my_min.add_instance(8, ['u','s','t'])
    my_min.compute_all_candidate_matches()
    pairs = my_min.get_candidate_pairs()
    
    print 'All candidate pairs'
    pprint.pprint(pairs)
    
    print 'Query on [x,y,z,h]'
    matches = my_min.candidate_query(['x','y','z','h'])
    pprint.pprint(matches)


if __name__ == "__main__":
    _test()