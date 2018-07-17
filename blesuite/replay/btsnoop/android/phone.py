from __future__ import unicode_literals
from executor import Executor

class Phone(object):

    def __init__(self, serial=None):
        self.serial = serial

    def shell(self, cmd):
        cmd = "adb shell " + cmd
        ret, out = Executor(cmd).execute()
        if ret != 0:
            raise ValueError("Could not execute adb shell " + cmd)
        return out

    def pull(self, src, dst):
        cmd = "adb pull " + src + " " + dst
        return Executor(cmd).execute()

    def push(self, src, dst):
        cmd = "adb push " + src + " " + dst
        return Executor(cmd).execute()

    def ls(self, path):
        out = self.shell("ls " + path)
        return out.splitlines()

    def start_app(self, pkg_name):
        cmd = 'monkey -p ' + pkg_name + ' -c android.intent.category.LAUNCHER 1'
        self.shell(cmd)