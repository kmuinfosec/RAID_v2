import os
import sys

from pycallgraph3 import PyCallGraph
from pycallgraph3 import Config
from pycallgraph3 import GlobbingFilter
from pycallgraph3.output import GraphvizOutput

from Main import main
from Utils import get_dir

def call_graph_filtered(
    
        function_,
        args,
        output_png="./call_graph_png",
        custom_include=None

    ):
    """A call graph generator filtered"""
    config = Config()
    config.trace_filter = GlobbingFilter(
        include=custom_include)
    graphviz = GraphvizOutput(output_file=output_png)

    with PyCallGraph(output=graphviz, config=config):
        function_(args)

def Analysis(args):
    call_graph_filtered(
        main,
        args,
        os.path.join("graph.png")
    )

if __name__ == "__main__":

    Analysis(sys.argv)
