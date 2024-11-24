import threading
from threading import Thread


class CustomThread(Thread):
    """

    """
    def __init__(self, func, args=(), kwargs={}):
        Thread.__init__(self)
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        self.result = self.func(*self.args, **self.kwargs)


    def get_result(self):
        return self.result

    def set_result(self, result):
        self.result = result
