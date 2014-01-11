'''
    Use single-linkage hierarchical clustering to build up a tree
    of clusters from a similarity list.
        - Similarities -> Hierarchical Clustering (Tree)

    Input: Similarities - a tuple (source, target, sim)
    Output: Hierarchical Cluster (as a networkx tree datatype)
'''

import os, sys
import traceback
import json
import optparse
import networkx as nx
import collections
import matplotlib.pyplot as plt
import pandas as pd

import data_hacking.lsh_sims as lsh_sims

class HCluster():
    '''
        Use single-linkage hierarchical clustering to build up a tree
        of clusters from a similarity list.
            - Similarities -> Hierarchical Clustering (Tree)
    '''

    def __init__(self, records, verbose=False):
        ''' Init for HCluster.  The records parameter can be either
            a dataframe series or a python list of features.
        '''

        ''' Trying to support python list, pandas DataFrames and pandas Series. '''
        if isinstance(records, list):
            self._record_type = 'list'
            self._get_row = lambda index: self._records[index]
        elif isinstance(records, pd.DataFrame):
            self._record_type = 'dataframe'
            self._get_row = lambda index: [str(x) for x in self._records.iloc[index].values.tolist()]
        elif isinstance(records, pd.Series):
            if isinstance(records.iloc[0], list):
                self._record_type = 'series'
                self._get_row = lambda index: self._records.iloc[index]
            else:
                print 'A Series must be a series of lists'
                print 'instead got a series of %s' % type(records.iloc[0])
                exit(1)
        else:
            print 'Unknown records type for LSHSimilarities(): %s' % type(records)
            exit(1)

        # Store a handle to the records
        self._records = records

        # Other class ivars
        self.sim_method = None
        self.agg_sim = 0.0
        self.verbose = verbose

    def vprint(self, args):
        if (self.verbose):
            for a in args:
                sys.stdout.write( a),
            sys.stdout.write()

    def set_sim_method(self, sim_function):
        '''
            The similarity function needs to take two args (features1, features2)
            and return the similarity of those features as a float between 0-1
        '''
        self.sim_method = sim_function

    def sims_to_hcluster(self, sim_list,  agg_sim=0.0):
        '''
            Use single-linkage hierarchical clustering to build up a tree
            of clusters from a similarity list.
                - Similarities -> Hierarchical Clustering (Tree)

            Input: sim_list - a tuple (sim, source, target)

            Output: Hierarchical Cluster (as a networkx digraph datatype), Graph_Root
        '''
        self.agg_sim = agg_sim

        # Generate labels
        labels = []
        if self._record_type == 'list':
            for record in self._records:
                labels.append(':'.join(record))
        else:
            for uuid in xrange(self._records.shape[0]):
                labels.append(':'.join(self._get_row(uuid)))


        # Sort the sim_list based on similarity, source, target
        # this triple key sort insures that the hierarchical tree
        # is constructed correctly, if this doesn't happen the
        # tree will be incorrect!
        sim_list.sort(key=lambda k: k, reverse=True)

        # Now construct a aggregation tree
        meta_nodes = collections.defaultdict(set)
        graph = nx.DiGraph()
        self.add_links_to_htree(graph, sim_list, labels)

        # Now wire up all the components to each other
        exemplars = []
        components = nx.weakly_connected_component_subgraphs(graph)
        for comp in components:

            # Find the root of this component
            root = self.find_root(graph, comp.nodes()[0])

            # Exemplar features for this component
            features = self.exemplar_features(graph, root)
            self.vprint(features)
            exemplars.append((root, features))

        # For each exemplar compute similarities to other examplars
        # Sort those similarities and add to hierarchical tree until
        # all components are wired together into one big tree
        self.vprint('Computing similarity on %d exemplars' % (len(exemplars)))
        exemplar_sims = []
        exemplar_zero_sims = []
        joined_exemplars = set()
        self.vprint('Created exemplar set (%d)" % (len(exemplars))')
        for node1, features1 in exemplars:
            for node2, features2 in exemplars:
                if (node1 == node2):
                    continue
                if (node1 in joined_exemplars and node2 in joined_exemplars):
                    continue
                sim = self.sim_method(features1, features2)
                if (sim > 0.0):
                    exemplar_sims.append((sim, node1, node2))
                else:
                    exemplar_zero_sims.append((sim, node1, node2))
                joined_exemplars.add(node1)
                joined_exemplars.add(node2)

        self.vprint('Sorting %d exemplar sim" % (len(exemplar_sims)+len(exemplar_zero_sims))')
        exemplar_sims.sort(key=lambda k:k, reverse=True)
        exemplar_zero_sims.sort(key=lambda k:k, reverse=True)

        # Now wire them up
        self.vprint('Wiring up %d exemplar sims' % (len(exemplar_sims)))
        for sim, source, target in exemplar_sims:
            root_source = self.find_root(graph, source)
            root_target = self.find_root(graph, target)
            meta_node = str(root_source)+'_'+str(root_target)
            graph.add_node(meta_node)
            graph.add_edge(meta_node, root_source, weight=sim, inv_weight=1.0-sim)
            graph.add_edge(meta_node, root_target, weight=sim, inv_weight=1.0-sim)

            # Add the meta label
            meta_label = self.meta_label(graph, meta_node)
            graph.node[meta_node]['label'] = meta_label

        # Logic around Root node
        if (exemplar_zero_sims):
            graph.add_node('Root', label='Root')
            #graph.add_edge('Root', last_meta_node, weight=0, inv_weight=1.0)
            for sim, source, target in exemplar_zero_sims:
                graph.add_edge('Root', source, weight=sim, inv_weight=1.0-sim)
                graph.add_edge('Root', target, weight=sim, inv_weight=1.0-sim)

        # Sanity check
        if (graph.number_of_nodes() == 0):
            print '<<<< WTF Error: Looks like an empty graph >>>>>'
            print 'Graph %d nodes %d edges' % (graph.number_of_nodes(), graph.number_of_edges())
            return None, None

        # Return both the graph and the root
        root_node = self.find_root(graph, graph.nodes()[0])
        return graph, root_node

    def add_meta_node(self, G, sim, source, target):

        # Find the roots of both source and target
        root_source = self.find_root(G, source)
        root_target = self.find_root(G, target)

        # Add the meta node
        meta_node = str(source)+'_'+str(target)
        G.add_node(meta_node)
        G.add_edge(meta_node, root_source, weight=sim, inv_weight=1.0-sim)
        G.add_edge(meta_node, root_target, weight=sim, inv_weight=1.0-sim)

        # Add the meta label
        meta_label = self.meta_label(G, meta_node)
        G.node[meta_node]['label'] = meta_label


    def check_edge_map(self, edge_map, G, node, sim):
        for target, t_sim in edge_map[node]:
            if (target in G and self.close_sim(t_sim, sim)):
                return target
        return None

    def close_sim(self, sim1, sim2):
        return True if abs(sim1-sim2) <= self.agg_sim else False

    def add_links_to_htree(self, graph, sim_list, labels=None):

        # Construct edge map to help find an existing nodes in the graph
        edge_map = collections.defaultdict(list)
        for sim, source, target in sim_list:
            edge_map[source].append((target,sim))
            edge_map[target].append((source,sim))

        # Construct H Tree
        for sim, source, target in sim_list:

            # Three cases
            # 1) Neither node is in the graph
            # 2) One node is in the graph
            #     a) the sim is the same/close
            #     b) the sim is different
            # 3) They are both in the graph

            # 1) Neither node is in the graph
            if (source not in graph and target not in graph):

                # Check edge map first before we go and add two new nodes and a meta node
                new_target = self.check_edge_map(edge_map, graph, source, sim)
                new_source = self.check_edge_map(edge_map, graph, target, sim)
                if (new_target):
                    target = new_target
                elif (new_source):
                    source = new_source

                # Okay nothing hit so we have to add everything
                else:
                    graph.add_node(source, label=labels[source])
                    graph.add_node(target, label=labels[target])

                    # Add the meta node
                    self.add_meta_node(graph, sim, source, target)
                    continue

            # 2) One node is in the graph (target)
            if (source not in graph):
                graph.add_node(source, label=labels[source])
                target_parent = self.find_parent(graph, target)

                # 2a) similarity is the same (or close)
                if self.close_sim(sim, graph.out_edges(target_parent, data=True)[0][2]['weight']):
                    graph.add_edge(target_parent, source, weight=sim, inv_weight=1.0-sim)
                    continue
                # 2b) similarity is NOT the same
                else:
                    self.add_meta_node(graph, sim, source, target)

            # 2) One node is in the graph (source)
            elif (target not in graph):
                graph.add_node(target, label=labels[target])
                source_parent = self.find_parent(graph, source)

                # 2a) similarity is the same (or close)
                if self.close_sim(sim, graph.out_edges(source_parent, data=True)[0][2]['weight']):
                    graph.add_edge(source_parent, target, weight=sim, inv_weight=1.0-sim)
                    continue
                # 2b) similarity is NOT the same
                else:
                    self.add_meta_node(graph, sim, target, source)

            # 3) They are both in the graph
            else:
                # If these have the same root than they are already 'linked'
                root_source = self.find_root(graph, source)
                root_target = self.find_root(graph, target)
                if root_source == root_target:
                    continue
                self.add_meta_node(graph, sim, source, target)


    def is_tree(self, G):
        if nx.number_of_nodes(G) != nx.number_of_edges(G) + 1:
            return False
        return nx.is_weakly_connected(G)

    def find_root(self, G, node):
        root = node
        while (G.predecessors(root)):
            root = G.predecessors(root)[0]
        return root

    def find_parent(self, G, node):
        return G.predecessors(node)[0]

    def common_features(self, G, root):
        successors = G.successors(root)
        if not successors: return '---'
        common = G.node[successors[0]]['label'].split(':')
        for node in successors[1:]:
            node_feature_set = set(G.node[node]['label'].split(':'))
            common = [f for f in common if f in node_feature_set]
        return ':'.join(common)

    def exemplar_features(self, G, root):
        return G.node[root]['label'].split(':')

    def is_meta_node(self, node_id):
        return not isinstance(node_id, int)

    def meta_label(self, G, root):
        return str(self.common_features(G, root))

    def graph_info(self, G):
        print G
        print G.graph
        print "Number of Nodes:", G.number_of_nodes()
        print "Number of Edges:", G.number_of_edges()
        print "Connected:", nx.is_strongly_connected(G)

    def plot_htree(self, h_tree, prog='neato', node_size=1500, figsize=(12,6)):

        # Now split graph up into different labels
        self.vprint('Adding labels to graph...')
        labels = {}
        for node in h_tree.nodes(data=True):
            labels[node[0]] = node[1]['label']

        # Find the root
        root_node = [n for n,d in h_tree.in_degree().items() if d==0][0]

        # Tree layout
        pos = nx.graphviz_layout(h_tree, root=root_node, prog=prog)
        plt.figure(figsize = figsize)
        nx.draw_networkx(h_tree, pos, node_size=node_size, alpha=1.0, node_color=[.4,.6,.4], with_labels=True, labels=labels)

        # Specifiy edge labels explicitly
        edge_labels=dict([((u,v,),str(d['weight'])[:4]) for u,v,d in h_tree.edges(data=True)])
        nx.draw_networkx_edge_labels(h_tree,pos,edge_labels=edge_labels)
        plt.show()

# Simple test of the hcluster functionality
def _test():

    import pprint

    # Construct a small dataset
    my_data = [
               ['a','b','c','d'],
               ['a','b','d'],
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
    lsh = lsh_sims.LSHSimilarities(my_data, mh_params=params)
    sims = lsh.batch_compute_similarities(distance_metric='jaccard', threshold=.01)

    print 'All similarity pairs'
    pprint.pprint(sims)

    print 'Query on [x,y,z,h]'
    matches = lsh.similarity_query(['x','y','z','h'])
    pprint.pprint(matches)

    print 'Top 5 on [x,y,z,h]'
    top_5 = lsh.top_N(['x','y','z','h'], my_data, 5)
    pprint.pprint(top_5)

    # Compute a hierarchical clustering from the similarity list
    h_clustering = HCluster(my_data)
    h_clustering.set_sim_method(lsh.jaccard_sim)
    h_tree, root = h_clustering.sims_to_hcluster(sims)

    # Plot the hierarchical tree
    h_clustering.plot_htree(h_tree)


if __name__ == "__main__":
    _test()
