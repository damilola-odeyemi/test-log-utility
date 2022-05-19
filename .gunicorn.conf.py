# Sample Gunicorn configuration file.

#
# Server socket
#
#   bind - The socket to bind.
#
#       A string of the form: 'HOST', 'HOST:PORT', 'unix:PATH'.
#       An IP is a valid HOST.
#
#   backlog - The number of pending connections. This refers
#       to the number of clients that can be waiting to be
#       served. Exceeding this number results in the client
#       getting an error when attempting to connect. It should
#       only affect servers under significant load.
#
#       Must be a positive integer. Generally set in the 64-2048
#       range.
#

bind = '127.0.0.1:8000'
backlog = 2048

#
# Worker processes
#
#   workers - The number of worker processes that this server
#       should keep alive for handling requests.
#
#       A positive integer generally in the 2-4 x $(NUM_CORES)
#       range. You'll want to vary this a bit to find the best
#       for your particular application's work load.
#
#   worker_class - The type of workers to use. The default
#       sync class should handle most 'normal' types of work
#       loads. You'll want to read
#       http://docs.gunicorn.org/en/latest/design.html#choosing-a-worker-type
#       for information on when you might want to choose one
#       of the other worker classes.
#
#       A string referring to a Python path to a subclass of
#       gunicorn.workers.base.Worker. The default provided values
#       can be seen at
#       http://docs.gunicorn.org/en/latest/settings.html#worker-class
#
#   worker_connections - For the eventlet and gevent worker classes
#       this limits the maximum number of simultaneous clients that
#       a single process can handle.
#
#       A positive integer generally set to around 1000.
#
#   timeout - If a worker does not notify the master process in this
#       number of seconds it is killed and a new worker is spawned
#       to replace it.
#
#       Generally set to thirty seconds. Only set this noticeably
#       higher if you're sure of the repercussions for sync workers.
#       For the non sync workers it just means that the worker
#       process is still communicating and is not tied to the length
#       of time required to handle a single request.
#
#   keepalive - The number of seconds to wait for the next request
#       on a Keep-Alive HTTP connection.
#
#       A positive integer. Generally set in the 1-5 seconds range.
#

# workers = 1
# worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

from multiprocessing import cpu_count
from os import environ
from sqlite3 import Timestamp


def max_workers():    
    return cpu_count()


bind = '0.0.0.0:' + environ.get('PORT', '8000')
max_requests = 1000
worker_class = 'gthread'
workers = max_workers()

#
#   spew - Install a trace function that spews every line of Python
#       that is executed when running the server. This is the
#       nuclear option.
#
#       True or False
#

spew = False

#
# Server mechanics
#
#   daemon - Detach the main Gunicorn process from the controlling
#       terminal with a standard fork/fork sequence.
#
#       True or False
#
#   raw_env - Pass environment variables to the execution environment.
#
#   pidfile - The path to a pid file to write
#
#       A path string or None to not write a pid file.
#
#   user - Switch worker processes to run as this user.
#
#       A valid user id (as an integer) or the name of a user that
#       can be retrieved with a call to pwd.getpwnam(value) or None
#       to not change the worker process user.
#
#   group - Switch worker process to run as this group.
#
#       A valid group id (as an integer) or the name of a user that
#       can be retrieved with a call to pwd.getgrnam(value) or None
#       to change the worker processes group.
#
#   umask - A mask for file permissions written by Gunicorn. Note that
#       this affects unix socket permissions.
#
#       A valid value for the os.umask(mode) call or a string
#       compatible with int(value, 0) (0 means Python guesses
#       the base, so values like "0", "0xFF", "0022" are valid
#       for decimal, hex, and octal representations)
#
#   tmp_upload_dir - A directory to store temporary request data when
#       requests are read. This will most likely be disappearing soon.
#
#       A path to a directory where the process owner can write. Or
#       None to signal that Python should choose one on its own.
#

daemon = False
raw_env = [
    'DJANGO_SECRET_KEY=something',
    'SPAM=eggs',
]
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

#
#   Logging
#
#   logfile - The path to a log file to write to.
#
#       A path string. "-" means log to stdout.
#
#   loglevel - The granularity of log output
#
#       A string of "debug", "info", "warning", "error", "critical"
#

errorlog = '-'
loglevel = 'info'
accesslog = '-'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

logfile = '-'
# capture_output = True
#
# Process naming
#
#   proc_name - A base to use with setproctitle to change the way
#       that Gunicorn processes are reported in the system process
#       table. This affects things like 'ps' and 'top'. If you're
#       going to be running more than one instance of Gunicorn you'll
#       probably want to set a name to tell them apart. This requires
#       that you install the setproctitle module.
#
#       A string or None to choose a default of something like 'gunicorn'.
#

proc_name = None

#
# Server hooks
#
#   post_fork - Called just after a worker has been forked.
#
#       A callable that takes a server and worker instance
#       as arguments.
#
#   pre_fork - Called just prior to forking the worker subprocess.
#
#       A callable that accepts the same arguments as after_fork
#
#   pre_exec - Called just prior to forking off a secondary
#       master process during things like config reloading.
#
#       A callable that takes a server instance as the sole argument.
#

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_fork(server, worker):
    pass

def pre_exec(server):
    server.log.info("Forked child, re-executing.")

def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")

    ## get traceback info
    import threading, sys, traceback
    id2name = {th.ident: th.name for th in threading.enumerate()}
    code = []
    for threadId, stack in sys._current_frames().items():
        code.append("\n# Thread: %s(%d)" % (id2name.get(threadId,""),
            threadId))
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename,
                lineno, name))
            if line:
                code.append("  %s" % (line.strip()))
    worker.log.debug("\n".join(code))

def worker_abort(worker):
    worker.log.info("worker received SIGABRT signal")

def post_request(worker, req, environ, resp):
    worker.log.info("hola")
    worker.log.info(req.__dir__())
    worker.log.info(resp.__dir__())
    worker.log.info(environ)
    worker.log.info("hola2")


# {
#     "method":"GET",
#     "uri":"/favicon.ico",
#     "path":"/favicon.ico",
#     "query":"",
#     "fragment":"",
#     "limit_request_line":4094,
#     "req_number":3,
#     "proxy_protocol_info":"None",
#     "cfg":<gunicorn.config.Config object at 0x102f1fa30>,
#     "unreader":<gunicorn.http.unreader.SocketUnreader object at 0x103c2fd60>,
#     "peer_addr":"(""127.0.0.1", 54424),
#     "version":(1, 1),

#     "headers":[
#         "(""HOST", "127.0.0.1:8000"")",
#         "(""CONNECTION", "keep-alive"")",
#         "(""SEC-CH-UA", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"101\", \"Google Chrome\";v=\"101\""")",
#         "(""SEC-CH-UA-MOBILE", "?0"")",
#         "(""USER-AGENT", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36"")",
#         "(""SEC-CH-UA-PLATFORM", "\"macOS\""")",
#         "(""ACCEPT", "*/*"")",
#         "(""SEC-FETCH-SITE", "same-origin"")",
#         "(""SEC-FETCH-MODE", "cors"")",
#         "(""SEC-FETCH-DEST", "empty"")",
#         "(""REFERER", "http://127.0.0.1:8000/admin/"")",
#         "(""ACCEPT-ENCODING", "gzip, deflate, br"")",
#         "(""ACCEPT-LANGUAGE", "en-GB,en-US;q=0.9,en;q=0.8"")",
#         "(""COOKIE", "mezzanine-admin-toolbar=; mezzanine-admin-tree=1; _ga=GA1.1.1640725688.1647153924; csrftoken=fzfGZxB6TIcPvqXAXnTXv8y3ud05YT14lWXN1ZcYUqXCGh59KrteR7br07mV7WpD"")"
#     ],
#     "trailers":[],
#     "body":<gunicorn.http.body.Body object at 0x1059ddd30>,
#     "scheme":"http",
#     "limit_request_fields":100,
#     "limit_request_field_size":8190,
#     "max_buffer_headers":819204
# }
# {
#     "req":<gunicorn.http.message.Request object at 0x1059abc70>,
#     "sock":<socket.socket fd=11,
#     "family=AddressFamily.AF_INET",
#     "type=SocketKind.SOCK_STREAM",
#     proto=0,
#     "laddr=(""127.0.0.1",8000),
#     "raddr=(""127.0.0.1", 54424)>,
#     "version":"gunicorn",
#     "status":"404 NOT FOUND",
#     "chunked":false,
#     "must_close":false,

#     "headers":[
#         "(""Content-Type", "text/html; charset=utf-8"")",
#         "(""Content-Length", "207"")"
#     ],
#     "headers_sent":true,
#     "response_length":207,
#     "sent":207,
#     "upgrade":false,
#     "cfg":<gunicorn.config.Config object at 0x102f1fa30>,
#     "status_code":404
# }



# def request_adapter(req, environ, resp):
#     timestamp = ""
#     request_id = ""
#     request_method	
#     request_url = 
#     request_size = 
#     status = 
#     response_size = 
#     user_agent = req['USER-AGENT']
#     remote_ip = environ['REMOTE_ADDR']
#     server_ip = req['HOST']
#     referer = environ['HTTP_REFERER']
#     latency = None
#     cache_lookup = None
#     cache_hit = None
#     cache_validated_with_origin_server = None
#     cache_fill_bytes = None
#     protocol = environ.get('SERVER_PROTOCOL', None)
#     headers = dict(req.headers)

# [
#     ('HOST', '127.0.0.1:8000'),
#     ('CONNECTION', 'keep-alive'),
#     ('SEC-CH-UA', '" Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101"'),
#     ('SEC-CH-UA-MOBILE', '?0'),
#     ('SEC-CH-UA-PLATFORM', '"macOS"'),
#     ('UPGRADE-INSECURE-REQUESTS', '1'),
#     ('USER-AGENT', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36'),
#     ('ACCEPT', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'),
#     ('SEC-FETCH-SITE', 'none'),
#     ('SEC-FETCH-MODE', 'navigate'),
#     ('SEC-FETCH-USER', '?1'),
#     ('SEC-FETCH-DEST', 'document'),
#     ('ACCEPT-ENCODING', 'gzip, deflate, br'),
#     ('ACCEPT-LANGUAGE', 'en-GB,en-US;q=0.9,en;q=0.8'),
#     ('COOKIE', 'mezzanine-admin-toolbar=; mezzanine-admin-tree=1; _ga=GA1.1.1640725688.1647153924; csrftoken=fzfGZxB6TIcPvqXAXnTXv8y3ud05YT14lWXN1ZcYUqXCGh59KrteR7br07mV7WpD')]

# # Timestamp

# # Hostname of the server

# # Request ID (to link related log messages together)

# # Requester IP address

# # Request method

# # Request URL

# # Request headers

# # Request protocol (usually HTTP or HTTPS)

# # Referrer

# # User-Agent HTTP request header

#  {
#      'wsgi.errors': <gunicorn.http.wsgi.WSGIErrorsWrapper object at 0x1065690d0>,
#      'wsgi.version': (1, 0),
#      'wsgi.multithread': True,
#      'wsgi.multiprocess': True,
#      'wsgi.run_once': False,
#      'wsgi.file_wrapper': <class 'gunicorn.http.wsgi.FileWrapper'>,
#      'wsgi.input_terminated': True,
#      'SERVER_SOFTWARE': 'gunicorn/20.1.0',
#      'wsgi.input': <gunicorn.http.body.Body object at 0x106569550>,
#      'gunicorn.socket': <socket.socket fd=11, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('127.0.0.1', 8000), raddr=('127.0.0.1', 51479)>,
#      'REQUEST_METHOD': 'GET',
#      'QUERY_STRING': '',
#      'RAW_URI': '/admin/',
#      'SERVER_PROTOCOL': 'HTTP/1.1',
#      'HTTP_HOST': '127.0.0.1:8000',
#      'HTTP_CONNECTION': 'keep-alive',
#      'HTTP_SEC_CH_UA': '" Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101"',
#      'HTTP_SEC_CH_UA_MOBILE': '?0',
#      'HTTP_SEC_CH_UA_PLATFORM': '"macOS"',
#      'HTTP_UPGRADE_INSECURE_REQUESTS': '1',
#      'HTTP_USER_AGENT': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36',
#      'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
#      'HTTP_SEC_FETCH_SITE': 'none',
#      'HTTP_SEC_FETCH_MODE': 'navigate',
#      'HTTP_SEC_FETCH_USER': '?1',
#      'HTTP_SEC_FETCH_DEST': 'document',
#      'HTTP_ACCEPT_ENCODING': 'gzip, deflate, br',
#      'HTTP_ACCEPT_LANGUAGE': 'en-GB,en-US;q=0.9,en;q=0.8',
#      'HTTP_COOKIE': 'mezzanine-admin-toolbar=; mezzanine-admin-tree=1; _ga=GA1.1.1640725688.1647153924; csrftoken=fzfGZxB6TIcPvqXAXnTXv8y3ud05YT14lWXN1ZcYUqXCGh59KrteR7br07mV7WpD',
#      'wsgi.url_scheme': 'http',
#      'REMOTE_ADDR': '127.0.0.1',
#      'REMOTE_PORT': '51479',
#      'SERVER_NAME': '0.0.0.0',
#      'SERVER_PORT': '8000', 
#      'PATH_INFO': '/admin/',
#      'SCRIPT_NAME': '',
#      'werkzeug.request': None
#     }