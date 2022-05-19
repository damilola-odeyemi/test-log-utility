"""
flask application
"""
import logging

from flask import Flask, jsonify


app = Flask(__name__)


# We check if we are running directly or not
if __name__ != '__main__':
    # if we are not running directly, we set the loggers
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)


@app.route('/')
def default_route():
    """Default route"""
    app.logger.debug("I'm a DEBUG message")
    app.logger.info("I'm an INFO message")
    app.logger.warning("I'm a WARNING message")
    app.logger.error("I'm a ERROR message")
    app.logger.critical("I'm a CRITICAL message")
    return jsonify('a return message')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
