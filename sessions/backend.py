from datetime import datetime

from django.contrib.session.backends.base import SessionBase

from django_appengine_utils import Session

class SessionStore(SessionBase):
    def __init__(self, session_key=None):
        super(SessionStore, self).__init__(session_key)

    def load(self):
        session_data = {}
        session = self._load_session(self.session_key)
        if session:
            if session.expire_date > datetime.now():
                try:
                    session_data = self.decode(session.session_data)
                except SuspiciousOperation:
                    self._invalid_session()
            else:
                self._invalid_session()
        return session_data or {}

    def save(self):
        session = Session(
            session_key = self.session_key,
            session_data = self.encode(self._session),
            expire_data = self.get_expiry_date()
        )
        session.put()

    def exists(self, session_key):
        session = self._load_session(session_key)
        return session is not None

    def _load_session(self, session_key):
        return Session.get_by_key_name('id:%s' % session_key)

    def _invalid_session(self):
        self.session_key = self._get_new_session_key()
        self._session_cache = {}
        self.save()
        self.modified = True
