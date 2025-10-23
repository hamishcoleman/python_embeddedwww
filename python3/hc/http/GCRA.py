"""Implement a simpler CGRA filter"""
#
# Imspired by https://dotat.at/@/2024-08-30-gcra.html
#
import time


class Filter:
    def __init__(self, rate_per_sec, burst_size):
        self.rate_per_sec = rate_per_sec
        self.window = burst_size / rate_per_sec
        self.ntime = 0

    def withdraw(self, cost):
        now = time.time()
        ntime = max(self.ntime, min(now - self.window, now))
        ntime += cost / self.rate_per_sec

        if now < ntime:
            return False

        self.ntime = ntime
        return True
