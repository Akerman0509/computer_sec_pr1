
# SECURITY WARNING: don't run with debug turned on in production!

DEBUG = True


# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'formatters': {
#         'sql_formatter': {
#             'format': '[%(asctime)s] %(levelname)s | %(message)s\n',
#             'datefmt': '%Y-%m-%d %H:%M:%S',
#         },
#     },
#     'handlers': {
#         'console': {
#             'level': 'DEBUG',
#             'class': 'logging.StreamHandler',
#             'formatter': 'sql_formatter',
#         },
#         'file': {
#             'level': 'DEBUG',
#             'class': 'logging.FileHandler',
#             'filename': 'django_queries.log',
#             'formatter': 'sql_formatter',
#         },
#     },
#     'loggers': {
#         'django.db.backends': {
#             'handlers': ['console', 'file'],
#             'level': 'DEBUG',
#             'propagate': False,
#         },
#     },
# }
