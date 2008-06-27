from google.appengine.ext import db

SESSION_KEY = '_auth_user_id'

def authenticate(username=None, password=None):
    """
    If the given username and password is valid, return a User object.
    """
    query = db.Query(User)
    user = query.filter('username =', username).get()
    if user.check_password(password):
        return user
    else:
        return None

def login(request, user):
    """
    Persist a user id and a backend in the request. This way a user doesn't
    have to reauthenticate on every request.
    """
    if user is None:
        user = request.user
    from datetime import datetime
    user.last_login = datetime.now()
    user.put()
    request.session[SESSION_KEY] = user.id
    if hasattr(request, 'user'):
        request.user = user

def logout(request):
    """
    Remove the authenticated user's ID from the request.
    """
    try:
        del request.session[SESSION_KEY]
    except KeyError:
        pass
    if hasattr(request, 'user'):
        from django.contrib.auth.models import AnonymousUser
        request.user = AnonymousUser()

def get_user(request):
    from django.contrib.auth.models import AnonymousUser
    try:
        user_id = request.session[SESSION_KEY]
        user = User.get_by_id(user_id)
    except KeyError:
        user = AnonymousUser()
    return user or AnonymousUser