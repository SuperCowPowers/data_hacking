#!/usr/bin/env python

from setuptools import setup

setup(name='data_hacking',
      version = '0.1',
      author='Brian Wylie',
      author_email='bwylie@visiblerisk.com',
      description='Modules for Data Hacking project',
      long_description=open('README.md').read(),
      install_requires=[ 'networkx','pygraphviz','pandas' ],
      url='http://clicksecurity.github.io/data_hacking',
      packages=['data_hacking', 'data_hacking.min_hash','data_hacking.lsh_sims',
                'data_hacking.hcluster','data_hacking.simple_stats'],
      classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: BSD License",
      ]
     )
