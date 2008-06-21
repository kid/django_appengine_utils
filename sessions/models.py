from google.appengine.ext import db

class Session(db.Model):
    session_key = db.StringProperty()
    session_data = db.BlobProperty()
    expire_date = db.DateTimeProperty()

    def put(self):
        self._key_name = 'id:%s' % self.session_key
        super(Session, self).put()
    save = put
