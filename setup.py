#!/usr/bin/env python

from setuptools import setup

from data_hacking import __version__

setup(name='data_hacking',
      version=__version__,
      author='Click',
      author_email='labs@clicksecurity.com',
      description='Modules for Data Hacking project',
      long_description=open('README.md').read(),
      install_requires=[ 'networkx','pygraphviz','pandas','matplotlib','numpy' ],
      url='http://clicksecurity.github.io/data_hacking',
      packages=['data_hacking', 'data_hacking.min_hash','data_hacking.lsh_sims',
                'data_hacking.hcluster','data_hacking.simple_stats','data_hacking.yara_signature'],
      classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: BSD License",
      ]
     )
