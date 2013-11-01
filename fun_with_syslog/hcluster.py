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

import lsh_sims

class HCluster():
    ''' 
        Use single-linkage hierarchical clustering to build up a tree
        of clusters from a similarity list.
            - Similarities -> Hierarchical Clustering (Tree)
    '''

    def __init__(self):
        ''' Init for HCluster. '''
        self.sim_method = None

    def set_sim_method(self, sim_function):
        ''' 
            The similarity function needs to take two args (features1, features2)
            and return the similarity of those features as a float between 0-1
        '''
        self.sim_method = sim_function

    def sims_to_hcluster(self, sim_list, node_attribute_list, labels=None):
        ''' 
            Use single-linkage hierarchical clustering to build up a tree
            of clusters from a similarity list.
                - Similarities -> Hierarchical Clustering (Tree)

            Input: sim_list - a tuple (source, target, sim)
                   node_attribute_list - list of attributes indexed by source/target
                                         so for instance [[a,b,c], [a,b,d], ...]
            Output: Hierarchical Cluster (as a networkx digraph datatype)
        '''

        # Generate labels if we need to
        if labels is None:
            labels = []
            for data in node_attribute_list:
                labels.append(':'.join(data)) 


        # Sort the sim_list based on similarity, source, target
        # this triple key sort insures that the hierarchical tree
        # is constructed correctly, if this doesn't happen the
        # tree will be incorrect!
        sim_list.sort(key=lambda k:k, reverse=True)

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
            print features
            exemplars.append((root, features))

        # For each exemplar compute similarities to other examplars
        # Sort those similarities and add to hierarchical tree until
        # all components are wired together into one big tree
        print "Computing similarity on %d exemplars" % (len(exemplars))
        exemplar_sims = []
        exemplar_zero_sims = []
        joined_exemplars = set()
        all_exemplars = set([x[0] for x in exemplars])
        print "Created exemplar set (%d)" % (len(exemplars))
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

        print "Sorting %d exemplar sim" % (len(exemplar_sims)+len(exemplar_zero_sims))
        exemplar_sims.sort(key=lambda k:k, reverse=True)
        exemplar_zero_sims.sort(key=lambda k:k, reverse=True)

        # Now wire them up
        print "Wiring up %d exemplar sims" % (len(exemplar_sims))
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
        if (not exemplar_zero_sims):
            root = self.find_root(graph, graph.nodes()[0])
            graph.add_node(root, label='Root')
        else:
            graph.add_node('Root', label='Root')
            #graph.add_edge('Root', last_meta_node, weight=0, inv_weight=1.0)
            for sim, source, target in exemplar_zero_sims:
                graph.add_edge('Root', source, weight=sim, inv_weight=1.0-sim)
                graph.add_edge('Root', target, weight=sim, inv_weight=1.0-sim)

        #graph = nx.weakly_connected_component_subgraphs(graph)[0]

        # Now compute 'maximal' spanning tree
        print "Computing Maximal Spanning Tree..."
        #tree = nx.minimum_spanning_tree(graph, weight='weight')
        #tree = nx.minimum_spanning_tree(graph.to_undirected(), weight='inv_weight')

        # Return the both the graph and the minimal spanning tree
        return graph, graph

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

    def add_links_to_htree_new(self, graph, sim_list, attributes):

        # Add all the nodes to the graph
        for sim, source, target in sim_list:
            graph.add_node(source, label=attributes[source]['label'])
            graph.add_node(target, label=attributes[target]['label'])

        # Construct edge map to help find an existing nodes in the graph
        edge_map = collections.defaultdict(list)
        for sim, source, target in sim_list:
            edge_map[source].append((target,sim))
            edge_map[target].append((source,sim))

        # Construct H Tree
        for sim, source, target in sim_list:
            root_target = self.find_root(graph, target)
            root_source = self.find_root(graph, source)

            # If they have the same root they are already 'linked'
            if root_source == root_target:
                continue

            # Does either have existing children?
            if (graph.out_edges(root_source)):
                if (sim == graph.out_edges(root_source, data=True)[0][2]['weight']):
                    graph.add_edge(root_source, target, weight=sim, inv_weight=1.0-sim)
                    continue
            if (graph.out_edges(root_target)):
                if (sim == graph.out_edges(root_target, data=True)[0][2]['weight']):
                    graph.add_edge(root_target, source, weight=sim, inv_weight=1.0-sim)
                    continue

            '''
            # Okay at this point we have to search edge_map, if that
            # fails then we add a meta node
            for target, t_sim in edge_map[source]:
                if (target in graph):
            '''
                
            self.add_meta_node(graph, sim, root_source, root_target)

    def check_edge_map(self, edge_map, G, node, sim):
        for target, t_sim in edge_map[node]:
            if (target in G and t_sim == sim):
                return target
        return None       

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
            #     a) the sim is the same
            #     b) the sim is different
            # 3) They are both in the graph
            
            # 1) Neither node is in the graph
            if (source not in graph and target not in graph):

                # Check edge map first before we go and add two new nodes and a meta node
                new_target = self.check_edge_map(edge_map, graph, source, sim)
                if (new_target):
                    root_target = self.find_root(graph, new_target)
                    graph.add_node(source, label=labels[source])
                    graph.add_edge(root_target, source, weight=sim, inv_weight=1.0-sim)
                    continue
                new_source = self.check_edge_map(edge_map, graph, target, sim)
                if (new_source):
                    root_source = self.find_root(graph, new_source)
                    graph.add_node(target, label=labels[source])
                    graph.add_edge(root_source, target, weight=sim, inv_weight=1.0-sim)
                    continue

                # Okay nothing hit so we have to add everything
                graph.add_node(source, label=labels[source])
                graph.add_node(target, label=labels[target])

                # Add the meta node
                self.add_meta_node(graph, sim, source, target)
                continue

            # 2) One node is in the graph (source)
            if (source not in graph):
                graph.add_node(source, label=labels[source])
                root_target = self.find_root(graph, target)
                
                # 2a) similarity is the same (source)
                if (sim == graph.out_edges(root_target, data=True)[0][2]['weight']):
                    graph.add_edge(root_target, source, weight=sim, inv_weight=1.0-sim)
                    continue
                # 2b) similarity is NOT the same
                else:
                    self.add_meta_node(graph, sim, source, target)
    
            # 2) One node is in the graph (target)
            elif (target not in graph):
                graph.add_node(target, label=labels[target])
                root_source = self.find_root(graph, source)
                
                # 2a) similarity is the same (target)
                if (sim == graph.out_edges(root_source, data=True)[0][2]['weight']):
                    graph.add_edge(root_source, target, weight=sim, inv_weight=1.0-sim)
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
    
    def common_features(self, G, root):
        features = None
        for node in G.successors(root):
            if features:
                features = features.intersection(set(G.node[node]['label'].split(':')))
            else:
                features = set(G.node[node]['label'].split(':'))
        return ':'.join(features)

    def exemplar_features(self, G, root):
        return set(G.node[root]['label'].split(':'))

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
        print "Adding labels to graph..."
        labels = {}
        for node in h_tree.nodes(data=True):
            labels[node[0]] = node[1]['label']

        # Find the root
        root_node = [n for n,d in h_tree.in_degree().items() if d==0][0]
        print "Root node = %s" % (root_node)

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
    h_clustering = HCluster()
    h_clustering.set_sim_method(lsh.jaccard_sim)
    h_graph, h_tree = h_clustering.sims_to_hcluster(sims, my_data)

    # Plot the hierarchical tree
    h_clustering.plot_htree(h_tree)


if __name__ == "__main__":
    _test()