# gunicorn -b 0.0.0.0:8000 -w 4 --log-config gunicorn_logging.conf runner:my_wsgi_flask_app

gunicorn -w 2 --threads 2 --log-config config.ini app:app
