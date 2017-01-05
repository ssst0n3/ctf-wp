from functools import wraps

from concurrent.futures import ThreadPoolExecutor
import time

pools = []


def clear_pools():
    count = 0
    global pools
    for p in pools:
        if not p.done():
            p.cancel()
            count += 1
    print count, "requests cancelled"
    pools = []


def check_pools_all_done():
    for p in pools:
        if not p.done():
            return False
    return True


class Tomorrow():
    def __init__(self, future, timeout):
        self._future = future
        self._timeout = timeout
        pools.append(future)

    def __getattr__(self, name):
        result = self._wait()
        return result.__getattribute__(name)

    def _wait(self):
        return self._future.result(self._timeout)


def async(n, base_type, timeout=None):
    def decorator(f):
        if isinstance(n, int):
            pool = base_type(n)
        elif isinstance(n, base_type):
            pool = n
        else:
            raise TypeError(
                "Invalid type: %s"
                % type(base_type)
            )

        @wraps(f)
        def wrapped(*args, **kwargs):
            return Tomorrow(
                pool.submit(f, *args, **kwargs),
                timeout=timeout
            )

        return wrapped

    return decorator


def threads(n, timeout=None):
    return async(n, ThreadPoolExecutor, timeout)

time.sleep(5)
