import datetime
import urllib

from django.contrib import auth
from django.db.models.manager import EmptyManager
from django.utils.encoding import smart_str

from google.appengine.ext import db

UNUSABLE_PASSWORD = '!' # This will never be a valid hash

def get_hexdigest(algorithm, salt, raw_password):
    """
    Returns a string of the hexdigest of the given plaintext password and salt
    using the given algorithm ('md5', 'sha1' or 'crypt').
    """
    raw_password, salt = smart_str(raw_password), smart_str(salt)
    if algorithm == 'crypt':
        try:
            import crypt
        except ImportError:
            raise ValueError('"crypt" password algorithm not supported in this environment')
        return crypt.crypt(raw_password, salt)
    # The rest of the supported algorithms are supported by hashlib, but
    # hashlib is only available in Python 2.5.
    try:
        import hashlib
    except ImportError:
        if algorithm == 'md5':
            import md5
            return md5.new(salt + raw_password).hexdigest()
        elif algorithm == 'sha1':
            import sha
            return sha.new(salt + raw_password).hexdigest()
    else:
        if algorithm == 'md5':
            return hashlib.md5(salt + raw_password).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(salt + raw_password).hexdigest()
    raise ValueError("Got unknown password algorithm type in password.")

def check_password(raw_password, enc_password):
    """
    Returns a boolean of whether the raw_password was correct. Handles
    encryption formats behind the scenes.
    """
    algo, salt, hsh = enc_password.split('$')
    return hsh == get_hexdigest(algo, salt, raw_password)

class UserManager(object):
    def create_user(self, username, email, password=None):
        "Creates and saves a User with the given username, e-mail and password."
        user = User(username=username, email=email.strip().lower())
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.put()
        return user

    def create_superuser(self, username, email, password):
        u = self.create_user(username, email, password)
        u.is_staff = True
        u.is_active = True
        u.is_superuser = True
        u.put()

class User(db.Expando):
    username = db.StringProperty(required=True)
    first_name = db.StringProperty()
    last_name = db.StringProperty()
    email = db.EmailProperty()
    password = db.StringProperty()
    is_staff = db.BooleanProperty(default=False, required=True)
    is_active = db.BooleanProperty(default=True, required=True)
    is_superuser = db.BooleanProperty(default=False, required=True)
    is_staff = db.BooleanProperty(default=False, required=True)
    last_login = db.DateTimeProperty(auto_now_add=True, required=True)
    date_joined = db.DateTimeProperty(auto_now_add=True, required=True)
    messages = db.ListProperty(unicode)

    objects = UserManager()

    def _get_id(self):
        return self.key().id() if self.is_saved() else None
    id = property(_get_id)

    def __unicode__(self):
        return self.username

    def get_absolute_url(self):
        return '/users/%s/' %  urllib.quote(smart_str(self.username))

    def is_anonymous(self):
        """Always returns False. This is a way of comparing User objects to anonymous users."""
        return False

    def is_authenticated(self):
        """Always return True. This is a way to tell if the user has been authenticated in templates."""
        return True

    def get_full_name(self):
        """Returns the first_name plus the last_name, with a space in between."""
        full_name = u'%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def set_password(self, raw_password):
        import random
        algo = 'sha1'
        salt = get_hexdigest(algo, str(random.random()), str(random.random()))[:5]
        hsh = get_hexdigest(algo, salt, raw_password)
        self.password = '%s$%s$%s' % (algo, salt, hsh)

    def check_password(self, raw_password):
        """
        Returns a boolean of whether the raw_password was correct.
        """
        return check_password(raw_password, self.password)

    def set_unusable_password(self):
        # Sets a value that will never be a valid hash
        self.password = UNUSABLE_PASSWORD

    def has_usable_password(self):
        return self.password != UNUSABLE_PASSWORD

    def get_group_permissions(self):
        """
        Returns a list of permission strings that this user has through
        his/her groups. This method queries all available auth backends.
        """
        raise NotImplementedError

    def get_all_permissions(self):
        raise NotImplementedError

    def has_perm(self, perm):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general.
        """
        # Inactive users have no permissions.
        if not self.is_active:
            return False

        # Superusers have all permissions.
        if self.is_superuser:
            return True

        raise NotImplementedError

    def has_perms(self, perm_list):
        """Returns True if the user has each of the specified permissions."""
        for perm in perm_list:
            if not self.has_perm(perm):
                return False
        return True

    def has_module_perms(self, app_label):
        raise NotImplementedError

    def get_and_delete_messages(self):
        raise NotImplementedError

    def email_user(self, subject, message, from_email=None):
        raise NotImplementedError

    def get_profile(self):
        raise NotImplementedError