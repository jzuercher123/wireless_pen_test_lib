from abc import ABC, abstractmethod
import logging

class BaseScanner(ABC):
    def __init__(self, core_framework, vulnerability_db):
        """
        Initializes the BaseScanner.

        :param core_framework: Instance of CoreFramework for accessing packet handling and event dispatching.
        :param vulnerability_db: Dictionary containing known vulnerabilities.
        """
        self.core = core_framework
        self.vulnerability_db = vulnerability_db
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def scan(self, target):
        """
        Executes the vulnerability scan on the specified target.

        :param target: The target wireless network or device identifier.
        """
        pass

    @abstractmethod
    def report(self):
        """
        Generates a report of the scan results.
        """
        pass
