"""Implement a simple Token Bucket Filter"""
import time


class Filter:
    def __init__(self, rate_per_sec, burst_size):
        self.rate_per_sec = rate_per_sec
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_add = int(time.time())

    def _withdraw(self, tokens):
        if self.tokens > tokens:
            self.tokens -= tokens
            return True
        return False

    def _check_add(self, now):
        elapsed = now - self.last_add
        if elapsed < 1:
            return

        tokens = self.tokens + elapsed * self.rate_per_sec
        if tokens > self.burst_size:
            tokens = self.burst_size

        self.tokens = tokens
        self.last_add = now

    def withdraw(self, tokens):
        if self._withdraw(tokens):
            return True

        self._check_add(time.time())
        return self._withdraw(tokens)
