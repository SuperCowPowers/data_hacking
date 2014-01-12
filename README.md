data_hacking
============
### Welcome to the Click Security Data Hacking Project

"Hacking in the sense of deconstructing an idea, hardware, anything and getting it to do something it wasn’t intended or to better understand how something works."(BSides CFP)

So hacking here means we want to quickly deconstruct data, understand what we've got and how to best utilize it for the problem at hand.

The primary motivation for these exercises is to explore the nexus of iPython, Pandas and Scikit Learn on security data of various kinds. The exercises will often intentionally show common missteps, warts in the data, paths that didn't work out that well and results that could definitely be improved upon. In general we're trying to capture what worked and what didn't, not only is that more realistic but often much more informative to the reader. :)

##### Python Modules Used:
  
  * iPython: Architecture for interactive computing and presentation (http://ipython.org)
  * Pandas: Python Data Analysis Library (http://pandas.pydata.org)
  * Scikit Learn (http://scikit-learn.org) Scikit-learn: Machine Learning in Python, Pedregosa et al., JMLR 12, pp. 2825-2830, 2011.
  * Matplotlib: Python 2D plotting library (http://matplotlib.org)

##### Exercises:
  
  * Detecting Algorithmically Generated Domains
    * GitHub Project
    * Notebook Viewer
  * Hierarchical Clustering of Syslogs
    * GitHub Project
    * Notebook Viewer
  * Exploration of data from Malware Domain List
    * GitHub Project
    * Notebook Viewer

#####Setup:

  * Required packages:
    * Brew
      * graphviz, freetype, zmq
    * Python
      * ipython, pandas, matplotlib, pyzmq, jinja2

  * Some of the exercises use packages from the data_hacking repository, to install those packages into your python site packages: 
  <pre>
     %> sudo python setup.py install
  </pre>
  * To uninstall:
  <pre>
     %> sudo pip uninstall data_hacking
  </pre>
  
#### Running the Notebooks:
Most of the notebooks will have relative paths to some resources, data files or images. In general the easiest way we found to run ipython on the notebooks is to change into that project directory and run ipython with this alias (put in your .bashrc or whatever):
<pre>alias ipython='ipython notebook --FileNotebookManager.notebook_dir=`pwd`'</pre>
<pre>
$ cd data_hacking/fun_with_syslog
$ ipython (as aliased above)
</pre>