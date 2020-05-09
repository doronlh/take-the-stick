import logging
import os
from colorlog import ColoredFormatter
from flask.logging import default_handler
from logging.handlers import RotatingFileHandler


def configure(app):
    app.logger.setLevel(logging.INFO)
    app.logger.removeHandler(default_handler)

    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    file_handler = RotatingFileHandler(filename=f'{log_dir}/app.log', maxBytes=1024 * 1024 * 500, backupCount=24)
    formatter = ColoredFormatter('%(log_color)s[%(asctime)s] %(levelname)s in %(module)s: %(message)s%(reset)s')
    file_handler.setFormatter(formatter)
    app.logger.addHandler(file_handler)
