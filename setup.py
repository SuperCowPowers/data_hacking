#!/usr/bin/env python

from setuptools import setup

from data_hacking import __version__

setup(name='data_hacking',
      version=__version__,
      author='Brian Wylie',
      author_email='bwylie@visiblerisk.com',
      description='Modules for Data Hacking project',
      long_description=open('README.md').read(),
      install_requires=[ 'networkx','pandas','matplotlib' ],
      url='http://clicksecurity.github.io/data_hacking',
      packages=['data_hacking', 'data_hacking.min_hash','data_hacking.lsh_sims',
                'data_hacking.hcluster','data_hacking.simple_stats'],
      classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: BSD License",
      ]
     )
