from random import randint
from Tribler.community.anontunnel import extendstrategies, selectionstrategies, lengthstrategies
from Tribler.community.anontunnel.community import CircuitReturnFactory
from Tribler.community.anontunnel.crypto import DefaultCrypto

__author__ = 'Chris'


class ProxySettings:
    def __init__(self):
        length = randint(1, 4)
        length = 2

        self.extend_strategy = extendstrategies.NeighbourSubset
        self.select_strategy = selectionstrategies.RandomSelectionStrategy(1)
        self.length_strategy = lengthstrategies.ConstantCircuitLengthStrategy(length)
        self.return_handler_factory = CircuitReturnFactory()
        self.crypto = DefaultCrypto()