class DatastoreBackend(object):
    """
    Authenticate against django_appengine_utils.auth.models.User
    """

    def authenticate(self, username=None, password=None):
        query = db.Query(User)
        user = query.filter('username =', username).get()
        if user.check_password(password):
            return user
        else:
            return None

    def get_group_permissions(self, user_obj):
        "Returns a list of permission strings that this user has through his/her groups."
        raise NotImplementedError

    def get_all_permissions(self, user_obj):
        raise NotImplementedError

    def has_perm(self, user_obj, perm):
        raise NotImplementedError

    def has_module_perm(self, user_obj, app_label):
        raise NotImplementedError

    def get_user(self, user_id):
        return User.get_by_id(user_id)