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

    def highest_gtest_scores(self, series_a, series_b, N=10, matches=10, reverse=False, min_volume=0):
        '''
            Inputs:
                    series_a, series_b: both should contain categorical data values (countries, protocols, etc).
                    N: How many of the top N keys in series_a should be returned.
                    matches: How many matches for each key should be returned.
                    reverse: Reverse sort, normal sort is highest g-score to lowest, reverse is opposite
                    min_volume: For some data you only want to see values with reasonable volume.

            Output:
                    There are 3 outputs,
                    - contingency table (raw counts)
                    - conditional distribution (row proportions)
                    - g_scores + everything in the first two outputs
        '''

        # Might Need Improvement:
        #     Expected counts, assuming uniform distribution under the null hypothesis.
        #     Which in this case means that series_a's categories will be equally
        #     distributed among series_b's categories.
        #
        #     Note: I might need some 'private' lessons from Alison Gibbs on exactly how
        #           this should be done, she is SO cute! (and also super smart of course :)
        #           http://www.youtube.com/watch?v=0nmxFpNBFIY
        mar_dist_a = series_a.value_counts().astype(float)  # Marginal distibution of A
        mar_dist_b = series_b.value_counts().astype(float)  # Marginal distibution of B
        total_count = float(sum(mar_dist_a))  # Both mar_dist_a/b will sum up to the same thing

        # Filter out anything less than the minimum volume parameter.
        # Kinda cheesy but handy to weed out low volume counts.
        mar_dist_a = mar_dist_a[mar_dist_a > min_volume]

        # Count up all the times that a category from series_a
        # matches up with a category from series_b. This is
        # basically a gigantic contingency table
        cont_table = collections.defaultdict(lambda : collections.Counter())
        for val_a, val_b in zip(series_a.values, series_b.values):
            cont_table[val_a][val_b] += 1

        # Create a dataframe
        # A dataframe with keys from series_a as the index, series_b_keys
        # as the columns and the counts as the values.
        dataframe = pd.DataFrame(cont_table.values(), index=cont_table.keys())
        dataframe.fillna(0, inplace=True)

        # Add a column for the marginal distribution of A
        dataframe['total'] = mar_dist_a

        # For each column (except total) compute conditional distribution (row proportions)
        columns = dataframe.columns.tolist()
        columns.remove('total')
        dataframe_cd = pd.DataFrame.copy(dataframe)
        for column in columns:
            dataframe_cd[column] = dataframe_cd[column] / dataframe_cd['total']

        # Now build the g-scores dataframe
        # Fixme: Probably a better/faster way to do this (sleepy right now)
        dataframe_g = pd.DataFrame.copy(dataframe)
        for column in columns:
            dataframe_g[column+'_cd'] = dataframe_cd[column]
            dataframe_g[column+'_exp'] = mar_dist_a * mar_dist_b[column] / total_count
            dataframe_g[column+'_g'] = [self.g_test_score(count, exp) for count, exp in zip(dataframe_g[column], dataframe_g[column+'_exp'])]


        # Return the 3 dataframes
        return dataframe, dataframe_cd, dataframe_g

    def g_test_score(self, count, expected):
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