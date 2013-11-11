import random

__author__ = 'chris'


class CircuitLengthStrategy(object):
    def __init__(self):
        pass

    def circuit_length(self):
        raise NotImplementedError()


class RandomCircuitLengthStrategy(CircuitLengthStrategy):
    def __init__(self, min, max):
        self.min = min
        self.max = max

    def circuit_length(self):
        return random.randrange(self.min, self.max)


class ConstantCircuitLengthStrategy(CircuitLengthStrategy):
    def __init__(self, desired_length):
        self.desired_length = desired_length

    def circuit_length(self):
        return self.desired_length