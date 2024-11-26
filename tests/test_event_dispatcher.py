import unittest
from unittest.mock import MagicMock
from wireless_pen_test_lib.core.event_dispatcher import EventDispatcher

class TestEventDispatcher(unittest.TestCase):
    def setUp(self):
        self.dispatcher = EventDispatcher()
        self.callback = MagicMock()

    def subscribes_callback_to_event_type(self):
        self.dispatcher.subscribe('test_event', self.callback)
        self.assertIn(self.callback, self.dispatcher.listeners['test_event'])

    def unsubscribes_callback_from_event_type(self):
        self.dispatcher.subscribe('test_event', self.callback)
        self.dispatcher.unsubscribe('test_event', self.callback)
        self.assertNotIn(self.callback, self.dispatcher.listeners['test_event'])

    def dispatches_event_to_subscribed_callbacks(self):
        self.dispatcher.subscribe('test_event', self.callback)
        self.dispatcher.dispatch('test_event', 42, key='value')
        self.callback.assert_called_once_with(42, key='value')

    def does_not_dispatch_event_to_unsubscribed_callbacks(self):
        self.dispatcher.subscribe('test_event', self.callback)
        self.dispatcher.unsubscribe('test_event', self.callback)
        self.dispatcher.dispatch('test_event', 42, key='value')
        self.callback.assert_not_called()

    def handles_exception_in_callback_gracefully(self):
        def faulty_callback(*args, **kwargs):
            raise ValueError("An error occurred")

        self.dispatcher.subscribe('test_event', faulty_callback)
        self.dispatcher.dispatch('test_event')
        self.assertTrue(self.dispatcher.logger.error.called)


if __name__ == '__main__':
    unittest.main()
# The EventDispatcher class is a simple
# implementation of the observer pattern.
# It allows objects to subscribe to specific

# events and receive notifications when
