"""Keep early uploads separate from downloads on a shared runner."""
from contextlib import contextmanager
import threading


class BandwidthGate:
    def __init__(self):
        self.condition = threading.Condition()
        self.upload_active = False
        self.upload_waiters = 0
        self.downloads = 0

    @contextmanager
    def upload(self):
        with self.condition:
            self.upload_waiters += 1
            try:
                self.condition.wait_for(lambda: not self.upload_active and not self.downloads)
                self.upload_active = True
            finally:
                self.upload_waiters -= 1
        try:
            yield
        finally:
            with self.condition:
                self.upload_active = False
                self.condition.notify_all()

    @contextmanager
    def download(self):
        with self.condition:
            self.condition.wait_for(lambda: not self.upload_active and not self.upload_waiters)
            self.downloads += 1
        try:
            yield
        finally:
            with self.condition:
                self.downloads -= 1
                self.condition.notify_all()
