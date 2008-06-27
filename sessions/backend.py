from datetime import datetime

from django.contrib.sessions.backends.base import SessionBase
from django.core.exceptions import SuspiciousOperation

from models import Session

class SessionStore(SessionBase):
    def __init__(self, session_key=None):
        super(SessionStore, self).__init__(session_key)

    def load(self):
        session_data = {}
        session = User.gql('WHERE session_key = :1 AND expire_data > :2', self.session_key, datetime.now()).get()
        if session:
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
            expire_date = self.get_expiry_date()
        )
        session.put()

    def exists(self, session_key):
        """Checks if the session key already exists in the datastore"""
        session = self._load_session(session_key)
        return session is not None

    def delete(self):
        session = _load_session(self.session_key)
        if session:
            session.delete()

    def _load_session(self, session_key):
        return Session.get_by_key_name('id:%s' % session_key)

    def _invalid_session(self):
        """Creates a new session for extra secucity"""
        self.session_key = self._get_new_session_key()
        self._session_cache = {}
        self.save()
        self.modified = True
