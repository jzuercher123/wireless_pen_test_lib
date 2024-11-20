from scapy.all import *
import logging
from abc import ABC, abstractmethod

# Base Handler Class
class PacketHandler(ABC):
    def __init__(self, event_dispatcher, next_handler=None):
        self.event_dispatcher = event_dispatcher
        self.next_handler = next_handler
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def handle(self, packet):
        pass