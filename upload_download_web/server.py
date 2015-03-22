import md5
import web
import time
import redis

urls = (
    '/login', 'Login',
    '/filelist', 'FileList',
    '/upload', 'Upload',
    '/download', 'Download',
    '/register', 'Register',
    '/setpasswd', 'SetPasswd',
)
app = web.application(urls, globals())
class User:
    def __init__(self, redis_client):
        self._redis = redis_client
        self._TOKEN_EXPIRE_TIME = 60 * 60 * 24 * 30
        self._PASSWD_SEC_KEY = "3021e68df9a7200135725c6331369a22"
    def authToken(self, uid, token):
        '''
        '''
        if timestamp + self._TOKEN_EXPIRE_TIME < time.time():
            return False
        return True
    def authPasswd(self, uid, passwd):
        passwd_key = md5.md5(uid[::-1] + passwd + uid + self._PASSWD_SEC_KEY).hexdigest()
        if self._redis.hget(uid, 'passwd_key') != passwd_key:
            return False
        return True
    def setPasswd(self, uid, passwd):
        passwd_key = md5.md5(uid[::-1] + passwd + uid + self._PASSWD_SEC_KEY).hexdigest()
        self._redis.hset(uid, 'passwd_key', passwd_key)
    def isAdmin(self, uid):
        if self._redis.hget(uid, 'level') != '0':
            return False
        return True
    def uploadFile(self, uid, filename):
        self._redis.lpush(uid + '_list', filename)
        sec_filename = md5.md5(uid + filename + str(time.time())).hexdigest()
        self._redis.lpush('file_ready', sec_filename)
class Login:
    def GET(self):

    def auth(self, uid, ):
if __name__ == '__main__':
    app.run()
