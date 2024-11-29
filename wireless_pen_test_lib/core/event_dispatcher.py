import logging
from collections import defaultdict

class EventDispatcher:
    """
    A simple event dispatcher that allows subscribing to and dispatching events.
    """
    def __init__(self):
        self.listeners = defaultdict(list)
        self.logger = logging.getLogger(self.__class__.__name__)

    def subscribe(self, event_type, callback):
        """
        Subscribes a callback function to a specific event type.
        :param event_type: The type/name of the event.
        :param callback: The function to call when the event is dispatched.
        """
        self.listeners[event_type].append(callback)
        self.logger.info(f"Subscribed to event '{event_type}': {callback.__name__}")

    def unsubscribe(self, event_type, callback):
        """
        Unsubscribes a callback function from a specific event type.
        :param event_type: The type/name of the event.
        :param callback: The function to remove from the event's listener list.
        """
        if callback in self.listeners[event_type]:
            self.listeners[event_type].remove(callback)
            self.logger.info(f"Unsubscribed from event '{event_type}': {callback.__name__}")

    def dispatch(self, event_type, *args, **kwargs):
        """
        Dispatches an event to all subscribed listeners.
        :param event_type: The type/name of the event.
        :param args: Positional arguments for the callback.
        :param kwargs: Keyword arguments for the callback.
        """
        self.logger.info(f"Dispatching event '{event_type}' to {len(self.listeners[event_type])} listeners.")
        for callback in self.listeners[event_type]:
            try:
                callback(*args, **kwargs)
            except Exception as e:
                self.logger.error(f"Error in callback '{callback.__name__}' for event '{event_type}': {e}")


# Example Usage
def on_event_fired(message):
    print(f"Event Fired: {message}")

dispatcher = EventDispatcher()
dispatcher.subscribe("on_event", on_event_fired)
dispatcher.dispatch("on_event", "Hello, World!")
# Output: Event Fired: Hello, World


