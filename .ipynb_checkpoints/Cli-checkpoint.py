{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "import logging\n",
    "import os\n",
    "import yaml\n",
    "\n",
    "import click\n",
    "import click_log\n",
    "from click.exceptions import UsageError\n",
    "from flaws2 import log\n",
    "from flaws2.__about__ import __version__\n",
    "\n",
    "click_log.basic_config(log)\n",
    "\n",
    "class YAML(click.ParamType):\n",
    "    name='yaml'\n",
    "    \n",
    "    def convert(self, value, param, ctx):\n",
    "        try:\n",
    "            with open(value, 'rb') as f:\n",
    "                return yaml.safe_load(f.read())\n",
    "        except(IOError) as e:\n",
    "            self.fail(f'Could not open file: {value}')\n",
    "        \n",
    "@click.command()\n",
    "@click_log.simple_verbosity_option(log)\n",
    "@click.option('--config', type=YAML(), help='Configuration file to use.')\n",
    "@click.option('--directory', type=str, help='Path to directory with CloudTrail files', required=True)\n",
    "@click.version_option(version=__version__)\n",
    "def cli(config, directory):\n",
    "    \"\"\"\n",
    "    Detect off instance key usage\n",
    "    \"\"\"\n",
    "    log.info('Detecting AWS Key usage off instance')\n",
    "    \n",
    "    if not os.path.exists(directory):\n",
    "        log.fatal('Invalid Directory Path')\n",
    "        \n",
    "    files = []\n",
    "    for file in os.listdir(directory):\n",
    "        files.append(os.path.join(directory, file))\n",
    "        \n",
    "    if not config:\n",
    "        config = {}\n",
    "        \n",
    "    api_calls_recorded = detect_off_instance_cloudtrail(config, files)\n",
    "    \n",
    "if __name__=='__main__':\n",
    "    try:\n",
    "        cli()\n",
    "    except KeyboardInterrupt:\n",
    "        logging.debug(\"Exiting due to KeyboardInterrupt\")"
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
