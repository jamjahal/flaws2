{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 4,
   "metadata": {},
   "outputs": [],
   "source": [
    "import re\n",
    "import ast\n",
    "import os.path\n",
    "import sys\n",
    "from setuptools import setup, find_packages\n",
    "\n",
    "_version_re=re.compile(r'__version__\\s+=\\s+(.*)')\n",
    "with open('flaws2/__about__.py', 'rb') as f:\n",
    "    DETECT_VERSION = str(ast.literal_eval(_version_re.search(\n",
    "        f.read().decode('utf-8')).group(1)))\n",
    "    \n",
    "\n",
    "# adding the src/ directory to the sys.path to be able to import ourselves\n",
    "\n",
    "sys.path.insert(0, ROOT)\n",
    "\n",
    "install_requirements = [\n",
    "    'boto3>=1.12.6',\n",
    "    'PyYAML>=5.3'\n",
    "]\n",
    "\n",
    "setup(\n",
    "    name='flaws2',\n",
    "    version=DETECT_VERSION,\n",
    "    long_description='Tool to identify potentially compromised AWS credentials',\n",
    "    packages=find_packages(),\n",
    "    install_requires=install_requirements,\n",
    "    entry_points= {\n",
    "        'console_scripts': [\n",
    "            'flaws2 = flaws2.cli:cli'\n",
    "        ]})"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.7.5"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 2
}
