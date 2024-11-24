import threading
import logging

class TaskScheduler:
    """
    A simple task scheduler that can run tasks sequentially or concurrently.
    """
    def __init__(self):
        self.tasks = []
        self.logger = logging.getLogger(self.__class__.__name__)

    def add_task(self, task, *args, **kwargs):
        """
        Adds a task to the scheduler.
        :param task: The function to execute.
        :param args: Arguments for the task.
        :param kwargs: Keyword arguments for the task.
        """
        self.tasks.append((task, args, kwargs))
        self.logger.info(f"Task added: {task.__name__}")

    def run_sequential(self):
        """
        Runs all tasks sequentially.
        """
        self.logger.info("Starting sequential task execution.")
        for task, args, kwargs in self.tasks:
            try:
                self.logger.info(f"Executing task: {task.__name__}")
                task(*args, **kwargs)
            except Exception as e:
                self.logger.error(f"Error executing task {task.__name__}: {e}")
        self.logger.info("Sequential task execution completed.")

    def run_concurrent(self, max_threads=5):
        """
        Runs tasks concurrently using threading.
        :param max_threads: Maximum number of concurrent threads.
        """
        self.logger.info("Starting concurrent task execution.")
        threads = []
        for task, args, kwargs in self.tasks:
            while threading.active_count() > max_threads:
                pass  # Wait until there's a free thread
            thread = threading.Thread(target=self._execute_task, args=(task, args, kwargs))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()
        self.logger.info("Concurrent task execution completed.")

    def _execute_task(self, task, args, kwargs):
        """
        Helper method to execute a single task.
        """
        try:
            self.logger.info(f"Executing task: {task.__name__}")
            task(*args, **kwargs)
        except Exception as e:
            self.logger.error(f"Error executing task {task.__name__}: {e}")
