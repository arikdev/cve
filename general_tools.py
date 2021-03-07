from time import time, sleep

def timer(func):
    def wrapper(*args, **qwargs):
        time_before = time()
        ret = func(*args, **qwargs)
        time_after = time()
        print('Elapsed time:' + str(time_after - time_before))
        return ret
    return wrapper

