# wireless_pen_test_lib/core/pool_manager.py

from typing import List
from wireless_pen_test_lib.core.database import Target

class Pool:
    """
    Pool Class

    Manages a collection of network targets.
    """
    def __init__(self):
        self.targets: List[Target] = []

    def add_target(self, target: Target):
        self.targets.append(target)

    def remove_target(self, target: Target):
        self.targets.remove(target)

    def get_all_targets(self) -> List[Target]:
        return self.targets
