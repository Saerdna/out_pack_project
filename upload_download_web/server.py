import md5
import rsa
import web
import time
import json
import redis

class User:
    publickey = None
    privatekey = None
    _redis = None
    def __init__(self):
        #self._redis = redis_client
        self._TOKEN_EXPIRE_TIME = 60 * 60 * 24 * 30
        self._PASSWD_SEC_KEY = "3021e68df9a7200135725c6331369a22"
        self.initKey()
        self.initRedis()
    @classmethod
    def initRedis(cls):
        if cls._redis == None:
            cls._redis = 0
    @classmethod
    def initKey(cls):
        if cls.publickey == None:
            with open('public.pem') as publickfile:
                p = publickfile.read()
                cls.publickey = rsa.PublicKey.load_pkcs1(p)

        if cls.privatekey == None:
            with open('private.pem') as privatekfile:
                p = privatekfile.read()
                cls.privatekey = rsa.PrivateKey.load_pkcs1(p)
    def authToken(self, uid, token):
        #authtoken = web.cookies().get('authToken')
        jsonbuff = rsa.decrypt(token, self.privatekey)
        userobj = json.loads(jsonbuff)
        if uid != userobj.get('uid', None) or userobj.get('timestamp', 0) + self._TOKEN_EXPIRE_TIME < time.time():
            return False
        return True
    
    def getToken(self, uid):
        obj = {'uid': uid, 'timestamp': int(time.time())}
        jsonbuff = json.dumps(obj)
        return rsa.encrypt(jsonbuff, self.publickey)
        #web.setcookie('authToken', rsa.encrypt(jsonbuff, self.publickey), self._TOKEN_EXPIRE_TIME)

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
    def addUploadFile(self, uid, filename):
        self._redis.lpush(uid + '_up_list', filename)
        sec_filename = md5.md5(uid + filename + str(time.time())).hexdigest()
        msg_obj = {'uid': uid, 'filename': sec_filename, 'sec_filename': sec_filename}
        self._redis.lpush('msg_queue', json.dumps(msg_obj))
    def downloadList(self, uid):
        listlen = self._redis.llen(uid + '_down_list')
        filelist = self._redis.lrange(uid + '_down_list', 0, listlen)
        return filelist
urls = (
    '/login', 'Login',
    '/filelist', 'FileList',
    '/upload', 'Upload',
    '/download', 'Download',
    '/register', 'Register',
    '/setpasswd', 'SetPasswd',
)
app = web.application(urls, globals())

class Register:
    def POST(self):
        req = web.input()
        token = web.cookies().get('authToken')
        uid = web.cookies().get('uid')
        user = User()
        if user.authToken(uid, token) == False or user.isAdmin(uid) == False:
            return False
         
class Login:
    def POST(self):
        req = web.input()
        uid = req.get('uid')
        passwd = req.get('passwd')
        user = User()
        if user.authPasswd(uid, passwd) == False:
            return False
        token = user.getToken(uid)
        web.setcookie('uid', uid)
        web.setcookie('authToken', token, user._TOKEN_EXPIRE_TIME)
        return True

class SetPasswd:
    def POST(self):
        req = web.input()
        token = web.cookies().get('authToken')
        uid = web.cookies().get('uid')
        user = User()
        if user.authToken(uid, token) == False:
            return False
        op_type = req.get('type')
        passwd = req.get('passwd')
        if op_type == 'admin':
            if user.isAdmin(uid) == False:
                return False
            uid = req.get('uid')
        user.setPasswd(uid, passwd)
        return True


if __name__ == '__main__':
    app.run()
