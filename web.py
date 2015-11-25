import json
from datetime import datetime, timedelta
from aiohttp import web
import jwt

from models import User

User.objects.create(email='user@email.com', password='password')


JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 20


def json_response(body='', **kwargs):
    kwargs['body'] = json.dumps(body or kwargs['body']).encode('utf-8')
    kwargs['content_type'] = 'text/json'
    return web.Response(**kwargs)


def login_required(func):
    def wrapper(request):
        if not getattr(request.user, 'id', None):
            return json_response({'message': 'Auth required'}, status=401)
        return func(request)
    return wrapper


async def index(request):
    return json_response({'user': str(request.user)})


@login_required
async def restricted(request):
    return json_response({'content': 'top secret'})


async def login(request):
    post_data = await request.post()

    try:
        user = User.objects.get(email=post_data['email'])
        user.match_password(post_data['password'])
    except (User.DoesNotExist, User.PasswordDoesNotMatch):
        return json_response({'message': 'Wrong credentials'}, status=400)

    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
    return json_response({'token': jwt_token.decode('utf-8')})


async def auth_middleware(app, handler):
    async def middleware(request):
        request.user = None
        jwt_token = request.headers.get('authorization', None)
        if jwt_token:
            try:
                payload = jwt.decode(jwt_token, JWT_SECRET,
                                     algorithms=[JWT_ALGORITHM])
            except (jwt.DecodeError, jwt.ExpiredSignatureError):
                return json_response({'message': 'Token invalid'}, status=400)

            request.user = User.objects.get(id=payload['user_id'])
        return await handler(request)
    return middleware


app = web.Application(middlewares=[auth_middleware])
app.router.add_route('GET', '/', index)
app.router.add_route('POST', '/login', login)
app.router.add_route('GET', '/restricted', restricted)
