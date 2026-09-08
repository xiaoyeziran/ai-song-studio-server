from main import app as fastapi_app
from a2wsgi import ASGIMiddleware
app = ASGIMiddleware(fastapi_app)
