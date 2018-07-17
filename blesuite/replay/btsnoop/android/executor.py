import subprocess


class Executor(object):
    """
    Wrapper for subprocess
    """

    def __init__(self, command):
        self.cmd = command

    def execute(self):
        """
        Executes the given command

        Returns a tuple of (exit code, stdout+stderr)
        """
        ret = ''
        exit_code = 0
        try:
            ret = subprocess.check_output(self.cmd, stderr=subprocess.STDOUT, shell=True)
            ret = ret.rstrip()
        except subprocess.CalledProcessError as error:
            exit_code = error.returncode
            ret = error.output.rstrip()
        return exit_code, ret
