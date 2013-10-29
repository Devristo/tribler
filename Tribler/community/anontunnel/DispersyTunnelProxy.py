import logging
from random import choice
import socket
import threading
import time
from traceback import print_exc
from Tribler.community.anontunnel.ConnectionHandlers.CircuitReturnHandler import CircuitReturnHandler, ShortCircuitReturnHandler
from Tribler.community.anontunnel.ProxyConversion import BreakPayload
from Tribler.dispersy.candidate import Candidate

__author__ = 'Chris'
MAX_CIRCUITS_TO_CREATE = 10

logger = logging.getLogger(__name__)

import random
from Observable import Observable

from collections import defaultdict
from ProxyConversion import DataPayload, ExtendPayload


class Circuit(object):
    """ Circuit data structure storing the id, status, first hop and all hops """

    @property
    def bytes_downloaded(self):
        return self.bytes_down[1]


    @property
    def bytes_uploaded(self):
        return self.bytes_up[1]


    def __init__(self, circuit_id, candidate=None):
        """
        Instantiate a new Circuit data structure

        :param circuit_id: the id of the candidate circuit
        :param candidate: the first hop of the circuit
        :return: Circuit
        """

        self.created = False
        self.id = circuit_id
        self.candidate = candidate
        self.hops = [candidate.sock_addr] if candidate else []
        self.goal_hops = 0

        self.timestamp = None

        self.times = []
        self.speed_up = []
        self.speed_down = []

        self.bytes_down = [0, 0]
        self.bytes_up = [0, 0]


class RelayRoute(object):
    def __init__(self, circuit_id, candidate):
        self.candidate = candidate
        self.circuit_id = circuit_id

        self.timestamp = None

        self.times = []
        self.speed = []
        self.bytes = [0, 0]


class DispersyTunnelProxy(Observable):
    @property
    def record_stats(self):
        return self._record_stats

    @record_stats.setter
    def record_stats(self, value):
        self._record_stats = value

        # clear old stats before recording new ones
        if value:
            with self.lock:
                for circuit in self.active_circuits:
                    circuit.speed_down = circuit.speed_down[:-2]
                    circuit.speed_up = circuit.speed_up[:-2]

                    circuit.times = []

    @property
    def active_circuits(self):
        # Circuit is active when it has recieved a CREATED for it and the final length and the length is 0
        return [circuit for circuit in self.get_circuits() if
                circuit.created and circuit.goal_hops == len(circuit.hops) and circuit.goal_hops > 0]

    def get_circuits(self):
        return self.circuits.values()

    def get_relays(self):
        return self.relay_from_to.values()

    def __init__(self, callback, community):
        """ Initialises the Proxy by starting Dispersy and joining
            the Proxy Overlay. """
        Observable.__init__(self)

        self.share_stats = False

        self.socket_server = community.socks_server
        self._record_stats = False

        self._exit_sockets = {}

        self.done = False
        self.circuits = {}

        # Add 0-hop circuit
        self.circuits[0] = Circuit(0)

        self.lock = threading.RLock()

        # Map destination address to the circuit to be used
        self.destination_circuit = {}

        # Routing tables
        self.relay_from_to = {}

        # Queue of EXTEND request, circuit id is key of the dictionary
        self.extension_queue = defaultdict(int)

        # Queue of EXTENDING 'FOR' requests
        self.extending_for = defaultdict(int)

        self.circuit_tag = {}

        self.community = None

        self.stats = {
            'bytes_enter': 0,
            'bytes_exit': 0,
            'bytes_returned': 0,
            'dropped_exit': 0
        }

        community.subscribe("on_create", self.on_create)
        community.subscribe("on_created", self.on_created)
        community.subscribe("on_extend", self.on_extend)
        community.subscribe("on_extended", self.on_extended)
        community.subscribe("on_data", self.on_data)
        community.subscribe("on_break", self.on_break)
        community.subscribe("on_member_heartbeat", self.on_member_heartbeat)
        community.subscribe("on_member_exit", self.on_member_exit)

        def calc_speeds():
            while True:
                t2 = time.clock()
                for c in self.circuits.values():
                    if c.timestamp is None:
                        c.timestamp = time.clock()
                    elif c.timestamp < t2:

                        c.speed_up.append((1.0 * c.bytes_up[1] - c.bytes_up[0]) / (t2 - c.timestamp))
                        c.speed_down.append((1.0 * c.bytes_down[1] - c.bytes_down[0]) / (t2 - c.timestamp))

                        if not self.record_stats:
                            c.speed_down = c.speed_down[:-1]
                            c.speed_up = c.speed_up[:-1]
                        else:
                            c.times.append(t2)

                        c.timestamp = t2
                        c.bytes_up = [c.bytes_up[1], c.bytes_up[1]]
                        c.bytes_down = [c.bytes_down[1], c.bytes_down[1]]

                for r in self.relay_from_to.values():
                    if r.timestamp is None:
                        r.timestamp = time.clock()
                    elif r.timestamp < t2:
                        r.speed.append((1.0 * r.bytes[1] - r.bytes[0]) / (t2 - r.timestamp))

                        if not self.record_stats:
                            r.speed = r.speed[:-1]
                        else:
                            r.times.append(t2)

                        r.timestamp = t2
                        r.bytes = [r.bytes[1], r.bytes[1]]

                yield 1.0

        def share_stats():
            while True:
                if self.share_stats:
                    logger.info("Sharing STATS")
                    for candidate in self.community.dispersy_yield_verified_candidates():
                        self.community.send(u"stats", candidate, (self._create_stats(),))

                yield 10.0

        def extend_circuits():
            while True:
                circuits_needing_extension = [c for c in self.circuits.values()
                                              if len(c.hops) < c.goal_hops
                    and self.extension_queue[c] == 0]

                for c in circuits_needing_extension:
                    self.extend_circuit(c)

                # Rerun every 5 seconds
                yield 5.0

        callback.register(extend_circuits, priority=-10)
        callback.register(calc_speeds, priority=-10)
        callback.register(share_stats, priority=-10)

        self.community = community

    def on_break(self, event):
        address = event.message.candidate.sock_addr
        msg = event.message.payload
        assert isinstance(msg, BreakPayload.Implementation)

        relay_key = (event.message.candidate, msg.circuit_id)
        community = self.community

        # If we can forward it along the chain, do so!
        if self.relay_from_to.has_key(relay_key):
            relay = self.relay_from_to[relay_key]

            community.send(u"break", relay.candidate, relay.circuit_id)
            logger.error("Forwarding BREAK packet from %s to %s", address, relay.candidate)

            # Route is dead :(
            del self.relay_from_to[relay_key]

        # We build this circuit but now its dead
        elif msg.circuit_id in self.circuits:
            self.break_circuit(msg.circuit_id)


    def on_create(self, event):
        """ Handle incoming CREATE message, acknowledge the CREATE request with a CREATED reply """
        address = event.message.candidate
        msg = event.message.payload

        logger.warning('We joined circuit %d with neighbour %s', msg.circuit_id, address.sock_addr)

        community = self.community
        community.send(u"created", address, msg.circuit_id)

    def on_created(self, event):
        """ Handle incoming CREATED messages relay them backwards towards the originator if necessary """

        msg = event.message.payload

        if msg.circuit_id in self.circuits:
            circuit = self.circuits[msg.circuit_id]
            circuit.created = True
            logger.warning('Circuit %d has been created', msg.circuit_id)

            self.fire("circuit_created", circuit=circuit)

            # Our circuit is too short, fix it!
            if circuit.goal_hops > len(circuit.hops) and self.extension_queue[circuit] == 0:
                logger.warning("Circuit %d is too short, is %d should be %d long", circuit.id, len(circuit.hops),
                               circuit.goal_hops)
                self.extend_circuit(circuit)

            if len(self.active_circuits) > 0:
                self.fire("on_ready", trigger_on_subscribe=True)

            self._process_extension_queue(circuit)
        elif not self.relay_from_to.has_key((event.message.candidate, msg.circuit_id)):
            logger.warning("Cannot route CREATED packet, probably concurrency overwrote routing rules!")
        else:
            created_for = self.relay_from_to[(event.message.candidate, msg.circuit_id)]

            extended_with = event.message.candidate

            community = self.community
            community.send(u"extended", created_for.candidate, created_for.circuit_id, extended_with.sock_addr)

            logger.warning('We have extended circuit (%s, %d) with (%s,%d)',
                           created_for.candidate.sock_addr,
                           created_for.circuit_id,
                           extended_with.sock_addr,
                           msg.circuit_id
            )

            self.fire("circuit_extended_for", extended_for=(created_for.candidate, created_for.circuit_id),
                      extended_with=(extended_with, msg.circuit_id))

            # transfer extending for queue to the next hop
            while self.extending_for[(created_for.candidate, created_for.circuit_id)] > 0:
                self.extending_for[(created_for.candidate, created_for.circuit_id)] -= 1

                community.send(u"extend", extended_with, msg.circuit_id)

    def on_data(self, event):
        """ Handles incoming DATA message, forwards it over the chain or over the internet if needed."""

        direct_sender_address = event.message.candidate.sock_addr
        msg = event.message.payload
        assert isinstance(msg, DataPayload.Implementation)

        relay_key = (event.message.candidate, msg.circuit_id)
        community = self.community

        # If we can forward it along the chain, do so!
        if self.relay_from_to.has_key(relay_key):
            relay = self.relay_from_to[relay_key]
            relay.bytes[1] += len(event.message.packet)

            community.send(u"data", relay.candidate, relay.circuit_id, msg.destination, msg.data, msg.origin)

            if __debug__:
                logger.info("Forwarding DATA packet from %s to %s", direct_sender_address, relay.candidate)

        # If message is meant for us, write it to output
        elif msg.circuit_id in self.circuits \
            and msg.destination == ("0.0.0.0", 0) \
            and event.message.candidate == self.circuits[msg.circuit_id].candidate:

            self.circuits[msg.circuit_id].bytes_down[1] += len(msg.data)
            self.stats['bytes_returned'] += len(msg.data)
            self.fire("on_data", data=msg, sender=direct_sender_address)

        # If it is not ours and we have nowhere to forward to then act as exit node
        elif msg.destination != ('0.0.0.0', 0):
            self.exit_data(msg.circuit_id, event.message.candidate, msg.destination, msg.data)

    def exit_data(self, circuit_id, return_candidate, destination, data):
        if __debug__:
            logger.info("EXIT DATA packet to %s", destination)

        self.circuits[0].bytes_up[1] += len(data)

        try:
            self.get_exit_socket(circuit_id, return_candidate).sendto(data, destination)
        except socket.error:
            self.stats['dropped_exit'] += 1
            pass


    def get_exit_socket(self, circuit_id, address):

        # If we don't have an exit socket yet for this socket, create one

        if not (circuit_id in self._exit_sockets):
            self._exit_sockets[circuit_id] = self.socket_server.create_udp_socket()

            # There is a special case where the circuit_id is None, then we act as EXIT node ourselves. In this case we
            # create a ShortCircuitHandler that bypasses dispersy by patching ENTER packets directly into the Proxy's
            # on_data event.
            if circuit_id is 0:
                return_handler = ShortCircuitReturnHandler(self._exit_sockets[circuit_id], self, address)
            else:
                # Otherwise incoming ENTER packets should propagate back over the Dispersy tunnel, we use the
                # CircuitReturnHandler. It will use the DispersyTunnelProxy.send_data method to forward the data packet
                return_handler = CircuitReturnHandler(self._exit_sockets[circuit_id], self, circuit_id, address)

            self.socket_server.start_listening_udp(self._exit_sockets[circuit_id], return_handler)

        return self._exit_sockets[circuit_id]

    def on_extend(self, event):
        """ Upon reception of a EXTEND message the message
            is forwarded over the Circuit if possible. At the end of
            the circuit a CREATE request is send to the Proxy to
            extend the circuit with. It's CREATED reply will
            eventually be received and propagated back along the Circuit. """

        msg = event.message.payload
        assert isinstance(msg, ExtendPayload.Implementation)

        relay_key = (event.message.candidate, msg.circuit_id)
        community = self.community

        # If we can forward it along the chain, do so!
        if relay_key in self.relay_from_to:
            relay = self.relay_from_to[relay_key]

            community.send(u"extend", relay.candidate, relay.circuit_id)
            return
        else:  # We are responsible for EXTENDING the circuit
            self.extend_for(event.message.candidate, msg.circuit_id)


    def extend_for(self, from_candidate, from_circuit_id):
        # Payload contains the address we want to invite to the circuit
        to_candidate = next(
            (x for x in self.community.dispersy_yield_verified_candidates()
             if x != from_candidate),
            None
        )

        if to_candidate:
            new_circuit_id = self._generate_circuit_id(to_candidate)

            with self.lock:
                from_key = (from_candidate, from_circuit_id)
                to_key = (to_candidate, new_circuit_id)

                if from_key not in self.relay_from_to and to_key not in self.relay_from_to:
                    self.relay_from_to[to_key] = RelayRoute(from_circuit_id, from_candidate)
                    self.relay_from_to[from_key] = RelayRoute(new_circuit_id, to_candidate)

            self.community.send(u"create", to_candidate, new_circuit_id)

            self.fire("circuit_extend", extend_for=(from_candidate, from_circuit_id),
                      extend_with=(to_candidate, new_circuit_id))
        else:
            self.extending_for[(from_candidate, from_circuit_id)] += 1


    def _process_extending_for_queue(self):
        for key in self.extending_for.keys():
            if self.extending_for[key] > 0:
                self.extending_for[key] -= 1
                self.extend_for(*key)

    def on_extended(self, event):
        """ A circuit has been extended, forward the acknowledgment back
            to the origin of the EXTEND. If we are the origin update
            our records. """

        msg = event.message.payload

        relay_key = (event.message.candidate, msg.circuit_id)
        community = self.community

        # If we can forward it along the chain, do so!
        if self.relay_from_to.has_key(relay_key):
            relay = self.relay_from_to[relay_key]
            community.send(u"extended", relay.candidate, relay.circuit_id, msg.extended_with)

        # If it is ours, update our records
        elif self.circuits.has_key(msg.circuit_id):
            circuit_id = msg.circuit_id
            extended_with = msg.extended_with

            circuit = self.circuits[circuit_id]

            addresses_in_use = [self.community.dispersy.wan_address]
            addresses_in_use.extend([
                x.sock_addr if isinstance(x, Candidate) else x
                for x in circuit.hops
            ])


            # CYCLE DETECTED!
            # Quick fix: delete the circuit!
            if extended_with in addresses_in_use:
                with self.lock:
                    del self.circuits[circuit_id]

                logger.error("[%d] CYCLE DETECTED %s in %s ", msg.circuit_id, extended_with, addresses_in_use)
                return

            # Decrease the EXTEND queue of this circuit if there is any
            # if circuit in self.extension_queue and self.extension_queue[circuit] > 0:
            circuit.hops.append(extended_with)
            logger.warning('Circuit %d has been extended with node at address %s and contains now %d hops', circuit_id,
                           extended_with, len(self.circuits[circuit_id].hops))

            self.fire("circuit_extended", circuit=circuit)

            # Our circuit is too short, fix it!
            if circuit.goal_hops > len(circuit.hops) and self.extension_queue[circuit] == 0:
                logger.warning("Circuit %d is too short, is %d should be %d long", circuit.id, len(circuit.hops),
                               circuit.goal_hops)
                self.extend_circuit(circuit)

            if circuit.goal_hops < len(circuit.hops):
                self.break_circuit(circuit_id)

            if len(self.active_circuits) > 0:
                self.fire("on_ready", trigger_on_subscribe=True)

    def _generate_circuit_id(self, neighbour):
        circuit_id = random.randint(1, 255)

        # prevent collisions
        while (neighbour, circuit_id) in self.relay_from_to:
            circuit_id = random.randint(1, 255)

        return circuit_id

    def create_circuit(self, first_hop, circuit_id=None):
        """ Create a new circuit, with one initial hop """

        # Generate a random circuit id that hasn't been used yet by us
        while circuit_id is None or circuit_id in self.circuits:
            circuit_id = self._generate_circuit_id(first_hop)

        circuit = Circuit(circuit_id, first_hop)
        circuit.goal_hops = random.randrange(1, 4)

        logger.warning('Circuit %d is to be created, we want %d hops', circuit.id, circuit.goal_hops)

        with self.lock:
            self.circuits[circuit_id] = circuit

        community = self.community
        community.send(u"create", first_hop, circuit_id)

        return self.circuits[circuit_id]

    def _process_extension_queue(self, circuit):
        queue = self.extension_queue[circuit]

        if circuit.created and queue > 0:
            self.extension_queue[circuit] -= 1
            logger.warning('Circuit %d is to be extended', circuit.id)

            community = self.community
            community.send(u"extend", circuit.candidate, circuit.id)

    def extend_circuit(self, circuit):
        self.extension_queue[circuit] += 1

        if circuit.created:
            self._process_extension_queue(circuit)

    def _create_stats(self):
        stats = {
            'bytes_enter': self.stats['bytes_enter'],
            'bytes_exit': self.stats['bytes_exit'],
            'bytes_return': self.stats['bytes_returned'],
            'circuits': [
                {
                    'bytes_down': c.bytes_down[1],
                    'bytes_up': c.bytes_up[1],
                    'speed_down': c.speed_down,
                    'speed_up': c.speed_up
                }
                for c in self.get_circuits()
            ],
            'relays': [
                {
                    'bytes': r.bytes[1],
                    'speed': r.speed
                }
                for r in self.get_relays()
            ]
        }

        return stats

    def on_member_heartbeat(self, event):
        candidate = event.candidate

        # We don't want to create too many circuits
        if len(self.circuits) > MAX_CIRCUITS_TO_CREATE:
            return

        if candidate not in [c.candidate for c in self.circuits.values()]:
            self.create_circuit(candidate)

        self._process_extending_for_queue()


    def send_data(self, payload, circuit_id=None, address=None, ultimate_destination=None, origin=None):
        assert address is not None or ultimate_destination != ('0.0.0.0', None)
        assert address is not None or ultimate_destination is not None

        with self.lock:
            try:
                # If no circuit specified, pick one from the ACTIVE LIST + 0-HOP
                if circuit_id is None:
                    # Each destination may be tunneled over a SINGLE different circuit
                    if ultimate_destination in self.destination_circuit \
                            and self.destination_circuit[ultimate_destination] in [c.id for c in self.active_circuits]:
                        circuit_id = self.destination_circuit[ultimate_destination]
                    else:
                        # Make sure the '0-hop circuit' is also a candidate for selection
                        circuit_id = choice(self.active_circuits + [self.circuits[0]]).id
                        self.destination_circuit[ultimate_destination] = circuit_id

                # If chosen the 0-hop circuit OR if there are no other circuits act as EXIT node ourselves
                if circuit_id == 0:
                    self.exit_data(0, None, ultimate_destination, payload)
                    return

                # If no address has been given, pick the first hop
                # Note: for packet forwarding address MUST be given
                if address is None:
                    if circuit_id in self.circuits and self.circuits[circuit_id].created:
                        address = self.circuits[circuit_id].candidate
                    else:
                        logger.warning("Dropping packets from unknown / broken circuit")
                        return

                self.community.send(u"data", address, circuit_id, ultimate_destination, payload, origin)

                if origin is None:
                    self.circuits[circuit_id].bytes_up[1] += len(payload)

                if __debug__:
                    logger.info("Sending data with origin %s to %s over circuit %d with ultimate destination %s",
                                origin, address, circuit_id, ultimate_destination)
            except Exception, e:
                logger.exception()

    def break_circuit(self, circuit_id):
        with self.lock:
            # Give other members possibility to clean up
            logger.error("Breaking circuit %d", circuit_id)

            # Delete from data structures
            if circuit_id in self.circuits:
                del self.circuits[circuit_id]

            tunnels_going_down = len(self.active_circuits) == 0
            # Delete any ultimate destinations mapped to this circuit
            for key, value in self.destination_circuit.items():
                if value == circuit_id:
                    del self.destination_circuit[key]
                    tunnels_going_down = True

            if tunnels_going_down:
                self.fire("on_down")

                if len(self.active_circuits):
                    self.fire("on_ready")

    def on_member_exit(self, event):
        """
        When a candidate is leaving the community we must break any associated circuits.
        """
        try:
            candidate = event.member
            assert isinstance(candidate, Candidate)

            # We must invalidate all routes in which the candidate takes part
            for c in self.circuits.values():
                if c.candidate == candidate:
                    self.break_circuit(c.id)

            for relay_key in self.relay_from_to.keys():
                relay = self.relay_from_to[relay_key]

                if relay_key[0] == candidate:
                    logger.error("Sending BREAK to (%s, %d)", relay.candidate, relay.circuit_id)
                    self.community.send(u"break", relay.candidate, relay.circuit_id)
                    del self.relay_from_to[relay_key]

                elif relay.candidate == candidate:
                    logger.error("Sending BREAK to (%s, %d)", relay_key[0], relay_key[1])
                    self.community.send(u"break", relay_key[0], relay_key[1])
                    del self.relay_from_to[relay_key]
        except BaseException, e:
            logger.exception(e)


