from abc import ABC, abstractmethod

class BaseProtocol(ABC):
    @abstractmethod
    def register(self, event_dispatcher):
        """
        Registers event listeners with the Event Dispatcher.
        """
        pass

    @abstractmethod
    def start(self):
        """
        Starts the protocol-specific operations (e.g., sniffing, injection).
        """
        pass

    @abstractmethod
    def stop(self):
        """
        Stops the protocol-specific operations.
        """
        pass
