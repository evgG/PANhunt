import json
import os
from datetime import datetime


CONFIG_FILE = os.environ.get('CONFIG_FILE') or 'config.json'


def load_config_file(config_file=CONFIG_FILE):
    with open(config_file) as _file:
        config = json.load(_file)
    config['outfile'] += datetime.now().strftime("%Y-%m-%d-%H%M%S")
    return config
