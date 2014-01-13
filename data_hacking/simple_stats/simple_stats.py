# Contingency Table, Two-way table, Joint Distribution, G-Scores
# Going off the reservation here, just couldn't find the right functionality elsewhere
# References: http://en.wikipedia.org/wiki/Contingency_table
#             http://en.wikipedia.org/wiki/G_test (Wikipedia)
#             http://udel.edu/~mcdonald/stathyptesting.html (Hypothesis Testing)

import pandas as pd
import numpy as np
import collections
import math
import heapq
import collections
import math
import operator
import matplotlib.pyplot

# This class is just for fun :)
class Pony():
    def __init__(self): self.l=[0];
    def score(self,s): self.l.append(s)
    def plot(self):
        matplotlib.pyplot.figure()
        pd.Series(self.l).cumsum().plot(label='Pony Futures')
        matplotlib.pyplot.legend(loc='best')

class FixedHeap(list):
    def __init__(self, N):
        self._N = N
        super(list, self).__init__()
    def push(self, item):
        if (len(self) == self._N):
            heapq.heappushpop(self,item)
        else:
            heapq.heappush(self, item)
    def sorted(self):
        return heapq.nlargest(self._N, self)
    def max(self):
        return heapq.nlargest(1, self)[0]

class GTest():
    ''' This is homegrown functionality for contingency table, and G-test
        for two pandas series with categorical (nominal) values. G-test is
        for goodness of fit to a distribution and for independence in contingency
        tables. It's related to chi-squared, multinomial and Fisher's exact test,
        please see http://en.wikipedia.org/wiki/G_test (Wikipedia).
        Disclaimer: We have gone off the reservation here. This code isn't generalized
                    and isn't well tested, there may be bugs (will be bugs),
                    please use another method if available.

    '''
    def __init__(self):
        ''' Init for GTest '''

    def highest_gtest_scores(self, series_a, series_b, N=10, matches=10, reverse=False, min_volume=None):
        '''
            Inputs:
                    series_a, series_b: both should contain categorical data values (countries, protocols, etc).
                    N: How many of the top N keys in series_a should be returned.
                    matches: How many matches for each key should be returned.
                    reverse: Reverse sort, normal sort is lowest to highest, reverse is opposite
                    min_volume: For some data you only want to see values with resonable volume.

            Output:
                    There are 3 outputs,
                    1) a_keys: A sorted list of keys from series_a
                    2) match_list: A matched list of dictionaries of the form {series_b_key: count}
                       the count is the number of times the a_key was coincident with the b_key.
                    3) df: A dataframe with keys from series_a as the index, series_b_keys as the
                       columns, and the counts as the values.

                    Note: Just including the max g-score in the output right now as the g-score
                    without context is kinda meaningless.
        '''

        # Might Need Improvement:
        #     Expected counts, assuming uniform distribution under the null hypothesis.
        #     Which in this case means that series_a's categories will be equally
        #     distributed among series_b's categories.
        #
        #     Note: I might need some private lessons from Alison Gibbs on exactly how
        #           this should be done, she is SO cute! (and also super smart of course :)
        #           http://www.youtube.com/watch?v=0nmxFpNBFIY
        total_counts_a = series_a.value_counts()
        total_count = float(sum(series_b.value_counts()))
        total_counts_b = series_b.value_counts() / total_count

        # Count up all the times that a category from series_a
        # matches up with a category from series_b. This is
        # basically a gigantic contingency table
        _cont_table = collections.defaultdict(lambda : collections.Counter())
        for val_a, val_b in zip(series_a.values, series_b.values):

            # Is there a minimum volume parameter
            if (not min_volume or total_counts_a[val_a] > min_volume):
                _cont_table[val_a][val_b] += 1

        # Now that we have a contingency table we can compare
        # the counts against the expected counts given our
        # null hypothesis that each category should have a
        # uniform distribution across all other categories.
        a_b_scores = []

        # Compute g-test scores
        for key_a, counter in _cont_table.iteritems():
            score_heap = FixedHeap(matches)
            for key_b, count in counter.iteritems():
                expected_count = total_counts_a[key_a]*total_counts_b[key_b]
                score = self._g_test_score(count, expected_count)
                score_heap.push((score, count, key_b))

            # We want to convert the sorted list into an ordered dictionary (for dataframe later)
            od = collections.OrderedDict([(item[2], item[1]) for item in score_heap.sorted()])

            # Now add the ordered dict to the meta list
            a_b_scores.append({'key':key_a, 'max_g': score_heap.max()[0], 'matches': od})

        # Sort the list of keys based on their highest g-score
        a_b_scores.sort(key=lambda k:k['max_g'], reverse=True)

        # Only pulling just the information we need before doing the output transformations
        if (reverse):
            pre_output = a_b_scores[-N:]
        else:
            pre_output = a_b_scores[:N]

        # Transform the data into the proper output forms
        a_keys = [item['key'] for item in pre_output]
        match_list = [item['matches'] for item in pre_output]
        df = pd.DataFrame(match_list, index=a_keys)
        return a_keys, match_list, df

    def _g_test_score(self, count, expected):
        #return count/expected
        ''' G Test Score for likelihood ratio stats '''
        if (count == 0):
            return 0
        else:
            return 2.0 * count * math.log(count/expected)


# Simple test of the functionality
def _test():

    import os
    import pprint
    import ast

    # Open a dataset (relative path)
    cwd = os.getcwd()
    file_path = os.path.join(cwd, 'data/test_data.csv')
    dataframe = pd.read_csv(file_path)
    dataframe.head()

    # Looking for correlations between sql names and status
    g_test = GTest()
    names, match_list, df = g_test.highest_gtest_scores(dataframe['name'], dataframe['status'], N=5)
    print '\n<<< Names with highest correlation to status >>>'
    pprint.pprint(zip(names, match_list))
    print df

if __name__ == "__main__":
    _test()