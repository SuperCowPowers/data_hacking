data_hacking
============

### Welcome to the Click Security Data Hacking Project
"Hacking in the sense of deconstructing an idea, hardware, anything and getting it to do something it wasn’t intended or to better understand how something works." _(BSides CFP)_ 

So hacking here means we want to quickly deconstruct data, understand what we've got and how to best utilize it for the problem at hand. 

The primary motivation for these exercises is to explore the nexus of IPython, Pandas and Scikit Learn on security data of various kinds. The exercises will often intentionally show common missteps, warts in the data, paths that didn't work out that well and results that could definitely be improved upon. In general we're trying to capture what worked and what didn't, not only is that more realistic but often much more informative to the reader. :)

#### Python Modules Used:
- [IPython](http://ipython.org): Architecture for interactive computing and presentation
- [Pandas](http://pandas.pydata.org): Python Data Analysis Library
- [Scikit Learn](http://scikit-learn.org): Machine Learning in Python, Pedregosa et al., JMLR 12, pp. 2825-2830, 2011.
- [Matplotlib](http://matplotlib.org): Python 2D plotting library 

### Exercises:
- Detecting Algorithmically Generated Domains
    - [Notebook Viewer](http://nbviewer.ipython.org/url/raw.github.com/ClickSecurity/data_hacking/master/dga_detection/DGA_Domain_Detection.ipynb)
    - [GitHub Project](https://github.com/ClickSecurity/data_hacking/tree/master/dga_detection)

- Hierarchical Clustering of Syslogs
    - [Notebook Viewer](http://nbviewer.ipython.org/url/raw.github.com/ClickSecurity/data_hacking/master/fun_with_syslog/Fun_Syslog.ipynb)
    - [GitHub Project](https://github.com/ClickSecurity/data_hacking/tree/master/fun_with_syslog)
    
- Exploration of data from Malware Domain List
    - [Notebook Viewer](http://nbviewer.ipython.org/url/raw.github.com/ClickSecurity/data_hacking/master/mdl_exploration/MDL_Data_Exploration.ipynb)
    - [Malware Domain List](http://www.malwaredomainlist.com)
    - [GitHub Project](https://github.com/ClickSecurity/data_hacking/tree/master/mdl_exploration)
    
- SQL Injection
    - [Notebook Viewer](http://nbviewer.ipython.org/url/raw.github.com/ClickSecurity/data_hacking/master/sql_injection/sql_injection.ipynb)
    - [GitHub Project](https://github.com/ClickSecurity/data_hacking/tree/master/sql_injection)
    
- Browser Agent Fingerprinting
    - [Notebook Viewer](http://nbviewer.ipython.org/url/raw.github.com/ClickSecurity/data_hacking/master/browser_fingerprinting/browser_fingerprinting.ipynb)
    - [GitHub Project](https://github.com/ClickSecurity/data_hacking/tree/master/browser_fingerprinting)
    
- PE File Classification 
    - [Notebook Viewer](http://nbviewer.ipython.org/url/raw.github.com/ClickSecurity/data_hacking/master/pefile_classification/pefile_classification.ipynb)
    - [GitHub Project](https://github.com/ClickSecurity/data_hacking/tree/master/pefile_classification)

- PCAP Exploration
    - [Notebook Viewer](http://nbviewer.ipython.org/url/raw.github.com/ClickSecurity/data_hacking/master/contagio_traffic_analysis/contagio_traffic_analysis.ipynb)
    - [GitHub Project](https://github.com/ClickSecurity/data_hacking/tree/master/contagio_traffic_analysis)


#####Setup:

  * Required packages:
    * Brew
      * graphviz, freetype, zmq
    * Python
      * ipython, pygraphviz, pandas, matplotlib, networkx, pyzmq, jinja2

  * Some of the exercises use packages from the data_hacking repository, to install those packages into your python site packages: 
  <pre>
     %> sudo python setup.py install
  </pre>
  * To uninstall:
  <pre>
     %> sudo pip uninstall data_hacking
  </pre>
  
#### Install IPython:
There's quite a bit of google results for this, we actually have mixed feelings about the IPython install instructions on the IPython page. The directions work but it directs you to download and install Anaconda or the free edition of Enthought Canopy. Both of these are prepackaged python distributions with a bunch of stuff like Numpy, Scipy, IPython, Matplotlib, Pandas, ... occasionally these will have a hitch and then you might be a bit SOL because StackOverflow is going to say 'WTF are those things? Just do '$pip install blah' or '$brew install blah'. 

So we recommend you be brave and do it the normal way... in particular this guy seems to have a pretty good write up for Mac installs:
  
  - [michaelmartinez: installing IPython](http://michaelmartinez.in/installing-ipython-notebook-on-mountain-lion.html)

#### Running the Notebooks:
Most of the notebooks will have relative paths to some resources, data files or images. In general the easiest way we found to run ipython on the notebooks is to change into that project directory and run ipython with this alias (put in your .bashrc or whatever):
<pre>alias ipython='ipython notebook --FileNotebookManager.notebook_dir=`pwd`'</pre>
<pre>
$ cd data_hacking/fun_with_syslog
$ ipython (as aliased above)
</pre>


[ ![Click Logo](http://raw.github.com/ClickSecurity/data_hacking/gh-pages/images/clicklogo_sm.png)](http://www.clicksecurity.com "Click Security")
