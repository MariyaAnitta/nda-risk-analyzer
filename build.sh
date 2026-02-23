#!/bin/bash
# Install setuptools FIRST so pkg_resources is available for crewai
pip install --upgrade setuptools
# Now install the rest of the dependencies
pip install -r requirements.txt
