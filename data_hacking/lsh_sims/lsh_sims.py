'''
    LSHSimilarities: Compute similarity between a large set of items using
                     Locality Sensitive Hashing (LSH). Specifically we're
                     employing Banded Min-Hash.

    Unlike conventional hash functions the goal of LSH is to maximize probability
    of "collision" of similar items rather than avoid collisions.

    - http://en.wikipedia.org/wiki/MinHash
    - http://en.wikipedia.org/wiki/Locality_sensitive_hashing
    - Mining of Massive Datasets(Chap 3) http://infolab.stanford.edu/~ullman/mmds/ch3.pdf

    Use Banded LSH to reduce pairwise similarity calcs.
    Right now support three distance metrics
        1) Jaccard Index (set based)  -- jaccard
        2) Levenshtein Similarity (order matters)  -- levenshtein
        3) Levenshtein Distance (experimental: order matters)  -- levenshtein_D

    Usage:
        import lsh_similarity as lsim
        my_sim = lsim.LSHSimilarities(records, mh_params=None)
            Input: records - a list of records (each record is a list of sparse features)
                   mh_params - a dictionary of parameters for min_hash see MinHash()
        sim_list = my_sim.batch_compute_similarities(distance_metric='jaccard', threshold=0.5)
            Output: Similarities - a tuple (source, target, sim)
'''

import os, sys
import data_hacking.min_hash as min_hash
import pandas as pd

class LSHSimilarities():
    '''
    Use Banded LSH to reduce pairwise similarity calcs.
    Right now support three distance metrics
        1) Jaccard Index (set based)  -- jaccard
        2) Levenshtein Similarity (order matters) -- levenshtein
        3) Levenshtein Distance (experimental: order matters) -- levenshtein_D
    '''

    def __init__(self, records, mh_params = None, verbose=False):
        ''' Init for LSHSimilarities. '''

        ''' Trying to support python list, pandas DataFrames and pandas Series. '''
        if isinstance(records, list):
            self._record_type = 'list'
            self._get_row = lambda index: self._records[index]
        elif isinstance(records, pd.DataFrame):
            self._record_type = 'dataframe'
            self._get_row = lambda index: [x for x in self._records.iloc[index].values.tolist()]
        elif isinstance(records, pd.Series):
            if isinstance(records.iloc[0], list):
                self._record_type = 'series'
                self._get_row = lambda index: self._records.iloc[index]
            else:
                print 'A Series must be a series of lists'
                print 'instead got a series of %s' % type(records.iloc[0])
                sys.exit(1)
        else:
            print 'Unknown records type for LSHSimilarities(): %s' % type(records)
            sys.exit(1)

        # Store a handle to the records
        self._records = records

        # Spin up MinHash class
        # Note: The parameters here are just defaults, if you want to set
        #       them just populate the mh_params dictionary.
        if mh_params:
            self._min_hash = min_hash.MinHash(**mh_params)
        else:
            self._min_hash = min_hash.MinHash(num_hashes=20, lsh_bands=5, lsh_rows=4, drop_duplicates=True)

        # Set verbose flag
        self.verbose = verbose

    def vprint(self, args):
        if (self.verbose):
            for a in args:
                sys.stdout.write( a),
            sys.stdout.write()

    def batch_compute_similarities(self, distance_metric='jaccard', threshold = 0.5):
        '''
        Use Banded LSH to reduce pairwise similarity calcs.
        Right now support three distance metrics
            1) Jaccard Index (set based)  -- jaccard
            2) Levenshtein Similarity (order matters)  -- levenshtein
            3) Levenshtein Distance (experimental: order matters) -- levenshtein_D
        '''

        # Add instances to the min_hash class
        self.vprint('Adding %d samples to minhash...' % (len(self._records)))
        if self._record_type == 'list':
            for uuid, record in enumerate(self._records):
                self._min_hash.add_instance(uuid, record)
        else:
            for uuid in xrange(self._records.shape[0]):
                self._min_hash.add_instance(uuid, self._get_row(uuid))

        # Build up the min hash signatures
        self.vprint('Computing All Candidate Matches...')
        self._min_hash.compute_all_candidate_matches()

        # Get Candidate Pairs
        candidates = self._min_hash.get_candidate_pairs()

        # Output some stats
        n_pairs = len(candidates)
        total_pairs = len(self._records)*len(self._records)
        print'%d (%.2f%% out of %d) pairs returned from MinHash' % \
              (n_pairs, n_pairs*100.0/total_pairs, total_pairs)

        # Now process all the candidates events pairs and explicity
        # compute similarities based on the specified distance metric
        matches = []
        for source, target in candidates:

            # Make sure the source and target aren't the same
            if (source == target):
                continue

            # Compute Levenshtein Similarity between source and target
            if (distance_metric == 'levenshtein'):
                sim = self.l_sim(self._get_row(source), self._get_row(target))
                if (sim > threshold):
                    if (source < target):
                        matches.append((sim, source, target))
                    else:
                        matches.append((sim, target, source))

            # Compute Levenshtein Distance between source and target
            elif (distance_metric == 'levenshtein_D'):
                distance = self.levenshtein(self._get_row(source), self._get_row(target))
                if (distance < threshold):
                    if (source < target):
                        matches.append((distance, source, target))
                    else:
                        matches.append((distance, target, source))

            # Compute Levenshtein Distance between source and target
            elif (distance_metric == 'levenshtein_tapered'):
                distance = self.levenshtein_tapered(self._get_row(source), self._get_row(target))
                if (distance < threshold):
                    if (source < target):
                        matches.append((distance, source, target))
                    else:
                        matches.append((distance, target, source))

            # Compute Levenshtein Similarity between source and target
            elif (distance_metric == 'l_tapered_sim'):
                sim = self.l_tapered_sim(self._get_row(source), self._get_row(target))
                if (sim > threshold):
                    if (source < target):
                        matches.append((sim, source, target))
                    else:
                        matches.append((sim, target, source))

            # Compute a Jaccard Distance
            elif (distance_metric == 'jaccard'):
                sim = self.jaccard_sim(self._get_row(source), self._get_row(target))
                if (sim > threshold):
                    if (source < target):
                        matches.append((sim, source, target))
                    else:
                        matches.append((sim, target, source))

            # Catch unknown distance metric
            else:
                print 'Unknown distance metric', distance_metric
                raise NotImplementedError

        self.vprint('LSH: %s matches out of %s candidates (adjust parameters if needed)' % (len(matches), len(candidates)))

        # Return the matches list
        return matches

    def similarity_query(self, query_item, distance_metric='jaccard', threshold = 0.1):
        '''
        Use Banded LSH to reduce the number of candidates.
        Right now support two distance metrics
            1) Jaccard Index (set based)  -- jaccard
            2) Levenshtein Similarity (order matters)  -- levenshtein
        '''

        # Get Candidate Pairs
        candidates = self._min_hash.candidate_query(query_item)

        # Output warning if candidates too high
        n_pairs = len(candidates)
        if (n_pairs > 5000):
            print 'Warning: %d candidates returned from MinHash' % n_pairs

        # Now process all the candidates events pairs and explicity
        # compute similarities based on the specified distance metric
        matches = []
        for target in candidates:

            # Compute Levenshtein Distance between source and target
            if (distance_metric == 'levenshtein'):
                sim = self.l_sim(query_item, self._get_row(target))
                if (sim > threshold):
                    matches.append((sim, target))

            # Compute a Jaccard Distance
            elif (distance_metric == 'jaccard'):
                sim = self.jaccard_sim(query_item, self._get_row(target))
                if (sim > threshold):
                    matches.append((sim, target))

            # Catch unknown distance metric
            else:
                print 'Unknown distance metric', distance_metric
                raise NotImplementedError
        if (n_pairs > 5000):
            print 'LSH: %s matches out of %s candidates (adjust parameters if needed)' % (len(matches), n_pairs)

        # Return the matches list
        return matches

    def top_N(self, query_item, labels, N, distance_metric='jaccard', threshold = 0.1):
            '''
                This is a convenience methods that shows the label data for the
                top N matches against a similarity_query
            '''

            # Run the similarity query, get the match list, sort it, look
            # up the labels for those indices and return that data + sim score
            matches = self.similarity_query(query_item, distance_metric, threshold)
            matches.sort(reverse=True)
            matches_data = []
            for sim, index in matches[:N]:
                matches_data.append({'sim':sim, 'label':labels[index]})

            # Return the matches labels
            return matches_data

    def top_sims_deprecated(self, query_list, N, distance_metric='jaccard'):
            '''
                This is a convenience methods that returns the highest sim
                for the query_item.
            '''

            # Run the similarity query, get the match list, sort it,
            # get the top sim and add it to the output sim
            output_sims = []
            for query_item in query_list:
                matches = self.similarity_query(query_item, distance_metric)
                if (not matches):
                    output_sims.append(0.0)
                else:
                    matches.sort(reverse=True)
                    agg_sims = sum([x[0] for x in matches[:N]])/float(N)
                    output_sims.append(agg_sims)

            return output_sims

    def levenshtein(self, seq1, seq2):
        ''' Compute Levenshtein distance between two sequences (strings/lists)
            Note: This is based on a code snippet from Michael Homer
                  http://mwh.geek.nz/2009/04/26/python-damerau-levenshtein-distance '''
        oneago = None
        thisrow = range(1, len(seq2) + 1) + [0]
        for x in xrange(len(seq1)):
            _twoago, oneago, thisrow = oneago, thisrow, [0] * len(seq2) + [x + 1]
            for y in xrange(len(seq2)):
                delcost = oneago[y] + 1
                addcost = thisrow[y - 1] + 1
                subcost = oneago[y - 1] + (seq1[x] != seq2[y])
                thisrow[y] = min(delcost, addcost, subcost)
        return thisrow[len(seq2) - 1]

    def l_sim(self, seq1, seq2):
        ''' Compute similarity between two sequences using Levenshtein distance '''
        return 1.0 - self.levenshtein(seq1, seq2)/float(max(len(seq1), len(seq2)))

    def l_tapered_sim(self, seq1, seq2):
        ''' Compute similarity between two sequences using Levenshtein distance '''
        return 1.0 - self.levenshtein_tapered(seq1, seq2)/float(max(len(seq1), len(seq2)))

    def levenshtein_tapered(self, seq1, seq2):
        ''' Compute Levenshtein distance between two sequences (strings/lists)
            with a taper of costs as you progress down the sequence '''
        max_len = float(max(len(seq1), len(seq2)))
        oneago = None
        thisrow = range(1, len(seq2) + 1) + [0]
        for x in xrange(len(seq1)):
            _twoago, oneago, thisrow = oneago, thisrow, [0] * len(seq2) + [x + 1]
            for y in xrange(len(seq2)):
                taper = 1.0 - min(x, y) / max_len
                delcost = oneago[y] + taper
                addcost = thisrow[y - 1] + taper
                subcost = oneago[y - 1] + (seq1[x] != seq2[y]) * taper
                thisrow[y] = min(delcost, addcost, subcost)
        return thisrow[len(seq2) - 1]

    def jaccard_sim(self, features1, features2):
        ''' Compute similarity between two sets using Jaccard similarity '''
        set1 = set(features1)
        set2 = set(features2)
        #return len(set1.intersection(set2))/float(len(set1.union(set2)))
        return len(set1.intersection(set2))/float(max(len(set1),len(set2)))

# Simple test of the lsh_sims functionality
def _test():

    import pprint

    # Construct a small dataset
    my_data = [['a','b','c','d'],
               ['a','b','c','e'],
               ['z','b','c','d'],
               ['a','b','e','d'],
               ['w','x','y','z'],
               ['x','y','z'],
               ['w','x','q','z','y'],
               ['r','s','t'],
               ['u','s','t']
               ]

    # Note: The parameters here are setup for feeding the results into a Hierarchical
    #       Clustering algorithm, which needs as many similarities as you can get
    params = {'num_hashes':20, 'lsh_bands':20, 'lsh_rows':1, 'drop_duplicates':True}
    lsh = LSHSimilarities(my_data, mh_params=params)
    sims = lsh.batch_compute_similarities(distance_metric='l_tapered_sim', threshold=0)

    print 'All similarity pairs'
    sims.sort(key=lambda x: x[0], reverse=True)
    for sim in sims:
        print '(%f)\n%s\n%s\n' % (sim[0], my_data[sim[1]], my_data[sim[2]])

    print 'Query on [x,y,z,h]'
    matches = lsh.similarity_query(['x','y','z','h'])
    pprint.pprint(matches)

    print 'Top 5 on [x,y,z,h]'
    top_5 = lsh.top_N(['x','y','z','h'], my_data, 5)
    pprint.pprint(top_5)


if __name__ == "__main__":
    _test()
