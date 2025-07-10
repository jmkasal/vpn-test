import time


class TimeoutDict(dict):

    class TimeoutItem:

        def __init__(self, data):
            self.last_time = time.time()
            self.data = data


    def __init__(self, max_time: float):
        super().__init__()
        self.max_time = max_time


    def __setitem__(self, key, value):
        item = self.TimeoutItem(value)
        super().__setitem__(key, item)

    def __getitem__(self, key):
        item = super().__getitem__(key)
        now = time.time()
        if now - item.last_time >= self.max_time:
            super().pop(key)
            raise KeyError
        item.last_time = now
        return item.data

    def get(self, __key):
        item = super().get(__key)
        now = time.time()
        if item:
            if now - item.last_time >= self.max_time:
                    super().pop(__key, None)
                    return None
            item.last_time = now
            return item.data
        return None

    def pop(self, __key):
        item = self.get(__key)
        if item:
            super().pop(__key)
            return item.data
        return None


def test():

    time_dict = TimeoutDict(5.0)

    time_dict['test'] = '1234'
    print(time_dict.get('test'))
    time.sleep(6)
    print(time_dict['test'])


if __name__ == '__main__':
    test()


