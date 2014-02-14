"""
AnonTunnel community module
"""

# Python imports
import hashlib
import sys
import threading
import random
import time
from collections import defaultdict

# Tribler and Dispersy imports
import twisted
from twisted.internet import defer
from twisted.internet.defer import AlreadyCalledError
from twisted.python.failure import Failure
from Tribler.Core.Utilities import encoding
from Tribler.dispersy.authentication import MemberAuthentication
from Tribler.dispersy.conversion import DefaultConversion
from Tribler.dispersy.destination import CommunityDestination
from Tribler.dispersy.distribution import LastSyncDistribution
from Tribler.dispersy.message import Message
from Tribler.dispersy.requestcache import NumberCache
from Tribler.dispersy.resolution import PublicResolution
from Tribler.dispersy.candidate import Candidate, WalkCandidate, \
    BootstrapCandidate
from Tribler.dispersy.community import Community

# AnonTunnel imports
from Tribler.community.anontunnel import crypto
from Tribler.community.anontunnel import extendstrategies
from Tribler.community.anontunnel import selectionstrategies
from Tribler.community.anontunnel import lengthstrategies
from globals import *
from Tribler.community.anontunnel.payload import StatsPayload, CreateMessage, \
    CreatedMessage, ExtendedMessage, \
    PongMessage, PingMessage, DataMessage
from Tribler.community.anontunnel.conversion import CustomProxyConversion, \
    ProxyConversion, int_to_packed, packed_to_int

__author__ = 'chris'

import logging

logger = logging.getLogger()


class ProxySettings:
    """
    Data structure containing settings, including some defaults,
    for the ProxyCommunity
    """

    def __init__(self):
        length = 1 #random.randint(1, 3)

        self.max_circuits = 0
        self.extend_strategy = extendstrategies.NeighbourSubset
        self.select_strategy = selectionstrategies.RoundRobinSelectionStrategy(
            self.max_circuits)
        self.length_strategy = lengthstrategies.ConstantCircuitLengthStrategy(
            length)
        self.crypto = crypto.DefaultCrypto()


class RelayRoute(object):
    """
    Relay object containing the destination circuit, socket address and whether
    it is online or not
    """
    def __init__(self, circuit_id, sock_addr):
        """
        @type sock_addr: (str, int)
        @type circuit_id: int
        @return:
        """

        self.sock_addr = sock_addr
        self.circuit_id = circuit_id
        self.online = False
        self.last_incoming = time.time()

    @property
    def ping_time_remaining(self):
        """
        The time left before we consider the relay inactive
        """

        too_old = time.time() - CANDIDATE_WALK_LIFETIME - 5.0
        diff = self.last_incoming - too_old
        return diff if diff > 0 else 0

    @property
    def bytes(self):
        """
        Number of bytes that have been sent to the destination address
        """

        return 0


class Circuit:
    """ Circuit data structure storing the id, state and hops """

    def __init__(self, circuit_id, goal_hops=0, candidate=None, proxy=None,
                 deferred=None):
        """
        Instantiate a new Circuit data structure
        :type proxy: ProxyCommunity
        :param circuit_id: the id of the candidate circuit
        :param candidate: the first hop of the circuit
        :return: Circuit
        """

        self.circuit_id = circuit_id
        self.candidate = candidate
        self._hops = []
        self.goal_hops = goal_hops

        self.deferred = deferred if deferred else defer.Deferred()

        self._extend_strategy = None
        self.last_incoming = time.time()

        if proxy:
            self.__stats = proxy.global_stats.circuit_stats[circuit_id]
        else:
            self.__stats = None

        self.unverified_hop = None
        """ :type : Hop """

        self.proxy = proxy

    @property
    def extend_strategy(self):
        return self._extend_strategy

    @extend_strategy.setter
    def extend_strategy(self, value):
        assert isinstance(value, extendstrategies.ExtendStrategy)
        self._extend_strategy = value

    @property
    def hops(self):
        return self._hops

    def add_hop(self, hop):
        self._hops.append(hop)

        if self.state == CIRCUIT_STATE_READY:
            self.deferred.callback(self)

    @property
    def online(self):
        """
        Whether the circuit can be considered online, i.e. if it has
        reached it's full length

        @rtype: bool
        """
        return self.goal_hops == len(self.hops)

    @property
    def state(self):
        """
        The circuit state, can be either:
         CIRCUIT_STATE_BROKEN, CIRCUIT_STATE_EXTENDING or CIRCUIT_STATE_READY
        @rtype: str
        """
        if self.hops is None:
            return CIRCUIT_STATE_BROKEN

        if len(self.hops) < self.goal_hops:
            return CIRCUIT_STATE_EXTENDING
        else:
            return CIRCUIT_STATE_READY

    @property
    def ping_time_remaining(self):
        """
        The time left before we consider the circuit inactive, when it returns
        0 a PING must be sent to keep the circuit, including relays at its hop,
        alive.
        """
        too_old = time.time() - 5.0
        diff = self.last_incoming - too_old
        return diff if diff > 0 else 0

    def __contains__(self, other):
        if isinstance(other, Candidate):
            # TODO: should compare to a list here
            return other == self.candidate

    def beat_heart(self):
        """
        Mark the circuit as active
        """
        self.last_incoming = time.time()

    @property
    def bytes_downloaded(self):
        """
        The total numbers of bytes downloaded over this circuit during its
         entire lifetime
        @rtype: long|None
        """
        return self.__stats.bytes_downloaded if self.__stats else None

    @property
    def bytes_uploaded(self):
        """
        The total numbers of bytes uploaded over this circuit during its
         entire lifetime
        @rtype: long|None
        """
        return self.__stats.bytes_uploaded if self.__stats else None

    def tunnel_data(self, destination, payload):
        return self.proxy.tunnel_data_to_end(destination, payload, self)

    def destroy(self, reason='unknown'):
        self._hops = None

        if not self.deferred.called:
            self.deferred.errback(
                Failure(Exception("Circuit broken, reason=%s" % reason)))

class Hop:
    """
    Circuit Hop containing the address, its public key and the first part of
    the Diffie-Hellman handshake
    """

    def __init__(self, address, pub_key, dh_first_part):
        """
        @param (str, int) address: the socket address of the hop
        @param M2Crypto.EC.EC_pub pub_key: the EC public key of the hop
        @param long dh_first_part: first part of the DH-handshake
        """
        self.address = address
        self.pub_key = pub_key
        self.session_key = None
        self.dh_first_part = dh_first_part

    @property
    def host(self):
        """
        The hop's hostname
        """
        return self.address[0]

    @property
    def port(self):
        """
        The hop's port
        """
        return self.address[1]

class TunnelObserver:
    def __init__(self):
        pass

    def on_break_circuit(self, circuit):
        pass

    def on_break_relay(self, relay_key):
        pass

    def on_state_change(self, community, state):
        pass

    def on_incoming_from_tunnel(self, community, circuit, origin, data):
        pass

    def on_exiting_from_tunnel(self, circuit_id, candidate, destination, data):
        pass

    def on_tunnel_stats(self, community, candidate, stats):
        pass

    def on_enter_tunnel(self, circuit_id, candidate, origin, payload):
        pass

    def on_send_data(self, circuit_id, candidate, ultimate_destination,
                     payload):
        pass

    def on_relay(self, from_key, to_key, direction, data):
        pass

    def on_unload(self):
        pass


class ProxyCommunity(Community):
    @classmethod
    def get_master_members(cls, dispersy):
        # generated: Wed Sep 18 22:47:22 2013
        # curve: high <<< NID_sect571r1 >>>
        # len: 571 bits ~ 144 bytes signature
        # pub: 170 3081a7301006072a8648ce3d020106052b8104002703819200040460829f9bb72f0cb094904aa6f885ff70e1e98651e81119b1e7b42402f3c5cfa183d8d96738c40ffd909a70020488e3b59b67de57bb1ac5dec351d172fe692555898ac944b68c730590f850ab931c5732d5a9d573a7fe1f9dc8a9201bc3cb63ab182c9e485d08ff4ac294f09e16d3925930946f87e91ef9c40bbb4189f9c5af6696f57eec3b8f2f77e7ab56fd8d6d63
        # pub-sha1 089515d307ed31a25eec2c54667ddcd2d402c041
        #-----BEGIN PUBLIC KEY-----
        # MIGnMBAGByqGSM49AgEGBSuBBAAnA4GSAAQEYIKfm7cvDLCUkEqm+IX/cOHphlHo
        # ERmx57QkAvPFz6GD2NlnOMQP/ZCacAIEiOO1m2feV7saxd7DUdFy/mklVYmKyUS2
        # jHMFkPhQq5McVzLVqdVzp/4fncipIBvDy2OrGCyeSF0I/0rClPCeFtOSWTCUb4fp
        # HvnEC7tBifnFr2aW9X7sO48vd+erVv2NbWM=
        #-----END PUBLIC KEY-----
        master_key = "3081a7301006072a8648ce3d020106052b810400270381920004" \
                     "0460829f9bb72f0cb094904aa6f885ff70e1e98651e81119b1e7" \
                     "b42402f3c5cfa183d8d96738c40ffd909a70020488e3b59b67de" \
                     "57bb1ac5dec351d172fe692555898ac944b68c730590f850ab93" \
                     "1c5732d5a9d573a7fe1f9dc8a9201bc3cb63ab182c9e485d08ff" \
                     "4ac294f09e16d3925930946f87e91ef9c40bbb4189f9c5af6696" \
                     "f57eec3b8f2f77e7ab56fd8d6d63".decode("HEX")

        master = dispersy.get_member(master_key)
        return [master]

    # noinspection PyMethodOverriding
    @classmethod
    def load_community(cls, dispersy, master, my_member, settings=None,
                       integrate_with_tribler=True):
        try:
            dispersy.database.execute(
                u"SELECT 1 FROM community WHERE master = ?",
                (master.database_id,)).next()
        except StopIteration:
            return cls.join_community(
                dispersy, master, my_member, my_member,
                settings, integrate_with_tribler=integrate_with_tribler
            )
        else:
            return super(ProxyCommunity, cls).load_community(
                dispersy, master, settings,
                integrate_with_tribler=integrate_with_tribler
            )

    @property
    def online(self):
        return self._online

    @online.setter
    def online(self, value):
        changed = value != self._online

        if changed:
            self._online = value
            for o in self.__observers:
                o.on_state_change(self, value)

    @property
    def crypto(self):
        """
        @rtype: Tribler.community.privatesemantic.crypto.elgamalcrypto.ElgamalCrypto
        """
        return self.dispersy.crypto

    def __init__(self, dispersy, master_member, settings=None,
                 integrate_with_tribler=True):
        """
        @type master_member: Tribler.dispersy.member.Member
        """
        self._original_on_introduction_request = None
        self._original_on_introduction_response = None
        Community.__init__(self, dispersy, master_member)

        self.lock = threading.RLock()

        self.settings = settings if settings else ProxySettings()
        # Custom conversion
        self.packet_prefix = "fffffffe".decode("HEX")

        self.__observers = []
        ''' :type : list of TunnelObserver'''

        self.proxy_conversion = CustomProxyConversion()
        self._message_handlers = defaultdict(lambda: lambda *args: None)
        ''' :type : dict[
            str,
            (
                int, Candidate,
                StatsPayload|Tribler.community.anontunnel.payload.BaseMessage
            ) -> bool]
        '''

        self.circuits = {}
        """ :type : dict[int, Circuit] """
        self.directions = {}

        self.relay_from_to = {}
        """ :type :  dict[((str, int),int),RelayRoute] """

        self.waiting_for = {}
        """ :type :  dict[((str, int),int), bool] """

        self._heartbeat_candidates = {}

        self.key = self.my_member.private_key
        self.session_keys = {}

        sr = random.SystemRandom()
        sys.modules["random"] = sr

        self.send_transformers = []
        self.receive_transformers = []
        ''' @type: dict[,(Candidate, int, str) -> ] '''
        self.relay_transformers = []
        self._message_filters = defaultdict(list)

        # Map destination address to the circuit to be used
        self.destination_circuit = {}
        ''' @type: dict[(str, int), int] '''

        self._online = False

        self._circuit_promises = []
        self._reservations = set()

        # Attach message handlers
        self._initiate_message_handlers()

        # Enable Crypto
        self.settings.crypto.enable(self)

        # Enable global counters
        from Tribler.community.anontunnel.stats import StatsCollector
        self.global_stats = StatsCollector(self)
        self.global_stats.start()

        # Listen to prefix endpoint
        dispersy.endpoint.listen_to(self.packet_prefix, self.handle_packet)
        dispersy.callback.register(self.check_ready)
        dispersy.callback.register(self._ping_circuits)

        if integrate_with_tribler:
            from Tribler.Core.CacheDB.Notifier import Notifier

            self.notifier = Notifier.getInstance()
        else:
            self.notifier = None

        def loop_discover():
            while True:
                try:
                    self.__discover()
                finally:
                    yield 5.0

        self.dispersy.callback.register(loop_discover)

    def __discover(self):
        circuits_needed = lambda: max(
            len(self._circuit_promises),
            self.settings.max_circuits
        )

        with self.lock:
            while circuits_needed():
                logger.debug("Need %d new circuits!", circuits_needed())
                goal_hops = self.settings.length_strategy.circuit_length()

                if goal_hops == 0:
                    deferred = self._circuit_promises.pop(0) if \
                        len(self._circuit_promises) else None

                    circuit_id = self._generate_circuit_id()
                    self.circuits[circuit_id] = Circuit(
                        circuit_id=circuit_id,
                        proxy=self,
                        deferred=deferred)
                else:
                    circuit_candidates = {c.candidate for c in
                                          self.circuits.values()}

                    candidates = (c for c
                                  in self.dispersy_yield_verified_candidates()
                                  if c not in circuit_candidates)

                    c = next(candidates, None)

                    if c is None:
                        break
                    else:
                        deferred = self._circuit_promises.pop(0) if \
                            len(self._circuit_promises) else None
                        self._create_circuit(c, goal_hops, deferred=deferred)

    def add_observer(self, observer):
        #assert isinstance(observer, TunnelObserver)
        self.__observers.append(observer)
        observer.on_state_change(self, self.online)

    def remove_observer(self, observer):
        self.__observers.remove(observer)

    def unload_community(self):
        for o in self.__observers:
            o.on_unload()

        Community.unload_community(self)

    def _initiate_message_handlers(self):
        self._message_handlers[MESSAGE_CREATE] = self.on_create
        self._message_handlers[MESSAGE_CREATED] = self.on_created
        self._message_handlers[MESSAGE_DATA] = self.on_data
        self._message_handlers[MESSAGE_EXTEND] = self.on_extend
        self._message_handlers[MESSAGE_EXTENDED] = self.on_extended
        self._message_handlers[MESSAGE_PING] = self.on_ping
        self._message_handlers[MESSAGE_PONG] = self.on_pong

    def initiate_conversions(self):
        return [DefaultConversion(self), ProxyConversion(self)]

    def initiate_meta_messages(self):
        return [Message(
            self
            , u"stats"
            , MemberAuthentication()
            , PublicResolution()
            , LastSyncDistribution(synchronization_direction=u"DESC",
                                   priority=128, history_size=1)
            , CommunityDestination(node_count=10)
            , StatsPayload()
            , self.dispersy._generic_timeline_check
            , self.on_stats
        )]

    def _initialize_meta_messages(self):
        super(ProxyCommunity, self)._initialize_meta_messages()

        self._original_on_introduction_request = None
        self._original_on_introduction_response = None

        # replace the callbacks for the dispersy-introduction-request and
        # dispersy-introduction-response messages
        meta = self._meta_messages[u"dispersy-introduction-request"]
        self._original_on_introduction_request = meta.handle_callback
        self._meta_messages[meta.name] = Message(
            meta.community, meta.name, meta.authentication,
            meta.resolution, meta.distribution, meta.destination,
            meta.payload, meta.check_callback, self.on_introduction_request,
            meta.undo_callback,
            meta.batch
        )

        meta = self._meta_messages[u"dispersy-introduction-response"]
        self._original_on_introduction_response = meta.handle_callback
        self._meta_messages[meta.name] = Message(
            meta.community, meta.name, meta.authentication,
            meta.resolution, meta.distribution, meta.destination,
            meta.payload, meta.check_callback, self.on_introduction_response,
            meta.undo_callback, meta.batch
        )

        assert self._original_on_introduction_request
        assert self._original_on_introduction_response

    def on_introduction_request(self, messages):
        try:
            return self._original_on_introduction_request(messages)
        finally:
            for message in messages:
                self.on_member_heartbeat(message, message.candidate)

    def on_introduction_response(self, messages):
        try:
            return self._original_on_introduction_response(messages)
        finally:
            for message in messages:
                self.on_member_heartbeat(message, message.candidate)

    def on_stats(self, messages):
        for message in messages:
            for o in self.__observers:
                o.on_tunnel_stats(self, message.candidate,
                                  message.payload.stats)

    def get_cached_candidate(self, sock_addr):
        if sock_addr in self._heartbeat_candidates:
            return self._heartbeat_candidates[sock_addr]
        else:
            circuit_candidate = next(
                (c.candidate for c in self.circuits.values() if
                 c.goal_hops > 0 and c.candidate.sock_addr == sock_addr),
                None)
            return circuit_candidate

    def send_stats(self, stats):
        def __send_stats():
            meta = self.get_meta_message(u"stats")
            record = meta.impl(authentication=(self._my_member,),
                               distribution=(self.claim_global_time(),),
                               payload=(stats,))

            logger.warning("Sending stats")
            self.dispersy.store_update_forward([record], True, False, True)

        self.dispersy.callback.register(__send_stats)

    def __handle_incoming(self, circuit_id, am_originator, candidate, data):
        # Transform incoming data using registered transformers
        for f in self.receive_transformers:
            data = f(candidate, circuit_id, data)

        # Try to parse the packet
        _, payload = self.proxy_conversion.decode(data)
        packet_type = self.proxy_conversion.get_type(data)
        str_type = MESSAGE_TYPE_STRING.get(packet_type)

        logger.debug(
            "GOT %s from %s:%d over circuit %d",
            str_type if str_type else 'unknown-type-%d' % ord(packet_type),
            candidate.sock_addr[0],
            candidate.sock_addr[1],
            circuit_id
        )

        # Call any message filter before handing it over to our own handlers
        payload = self._filter_message(circuit_id, candidate,
                                       packet_type, payload, )

        if not payload:
            logger.warning("IGNORED %s from %s:%d over circuit %d",
                           str_type, candidate.sock_addr[0],
                           candidate.sock_addr[1], circuit_id)
            return

        if am_originator:
            self.circuits[circuit_id].beat_heart()

        result = self._message_handlers[packet_type](circuit_id, candidate, payload)

        if result:
            self.dict_inc(self.dispersy.statistics.success, str_type)
        else:
            self.dict_inc(self.dispersy.statistics.success,
                          str_type + '-ignored')
            logger.debug("Prev message was IGNORED")

    def __relay(self, circuit_id, data, relay_key, sock_addr):
        # First, relay packet if we know whom to forward message to for
        # this circuit. This happens only when the circuit is already
        # established with both parent and child and if the node is not
        # waiting for a CREATED message from the child

        direction = self.directions[relay_key]
        next_relay = self.relay_from_to[relay_key]

        for f in self.relay_transformers:
            data = f(direction, sock_addr, circuit_id, data)

        this_relay_key = (next_relay.sock_addr, next_relay.circuit_id)

        if this_relay_key in self.relay_from_to:
            this_relay = self.relay_from_to[this_relay_key]
            this_relay.last_incoming = time.time()

            for o in self.__observers:
                # TODO: check whether direction is set correctly here!
                o.on_relay(this_relay_key, next_relay, direction, data)

        packet_type = self.proxy_conversion.get_type(data)

        str_type = MESSAGE_TYPE_STRING.get(
            packet_type, 'unknown-type-%d' % ord(packet_type)
        )

        logger.debug(
            "GOT %s from %s:%d over circuit %d", str_type,
            sock_addr[0], sock_addr[1], circuit_id
        )

        self.send_packet(
            destination=Candidate(next_relay.sock_addr, False),
            circuit_id=next_relay.circuit_id,
            message_type=packet_type,
            packet=data,
            relayed=True
        )

        self.dict_inc(self.dispersy.statistics.success, str_type + '-relayed')

    def handle_packet(self, sock_addr, orig_packet):
        """
        @param (str, int) sock_addr: socket address in tuple format
        @param orig_packet:
        @return:
        """
        packet = orig_packet[len(self.packet_prefix):]
        circuit_id, data = self.proxy_conversion.get_circuit_and_data(packet)
        relay_key = (sock_addr, circuit_id)

        is_relay = circuit_id > 0 and relay_key in self.relay_from_to and \
                   not relay_key in self.waiting_for
        is_originator = not is_relay and circuit_id in self.circuits
        is_initial = not is_relay and not is_originator

        try:
            if is_relay:
                return self.__relay(circuit_id, data, relay_key, sock_addr)

            # We don't know this circuit id, so it's the initial message
            # for this circuit
            if is_initial:
                candidate = self.get_cached_candidate(sock_addr)
            else:
                candidate = Candidate(sock_addr, False)

            if not candidate:
                raise Exception("No known candidate at {0}, "
                                "bailing out!".format(sock_addr))

            self.__handle_incoming(circuit_id, is_originator, candidate, data)

        except Exception as e:
            logger.exception(
                "Incoming message could not be handled."
                "connection. INITIAL={0}, ORIGINATOR={1}, RELAY={2}"
                .format(is_initial, is_originator, is_relay))

            if relay_key in self.relay_from_to:
                del self.relay_from_to[relay_key]
            elif circuit_id in self.circuits:
                self.remove_circuit(
                    circuit_id,
                    "Bad crypto, possible old circuit: {0}".format(e.message))
            else:
                logger.debug("Got an encrypted message I can't encrypt. "
                             "Dropping packet, probably old.")

    class CircuitRequestCache(NumberCache):
        @staticmethod
        def create_number(force_number=-1):
            return force_number if force_number >= 0 else NumberCache.create_number()

        @staticmethod
        def create_identifier(number, force_number=-1):
            assert isinstance(number, (int, long)), type(number)
            return u"request-cache:circuit-request:%d" % (number,)

        def __init__(self, community, force_number):
            NumberCache.__init__(self, community.request_cache, force_number)
            self.community = community

            self.circuit = None
            """ :type : Tribler.community.anontunnel.community.Circuit """

        @property
        def timeout_delay(self):
            return 5.0

        def on_extended(self, extended_message):
            """
            :type extended_message : ExtendedMessage
            """
            unverified_hop = self.circuit.unverified_hop

            session_key = pow(extended_message.key,
                              unverified_hop.dh_first_part,
                              DIFFIE_HELLMAN_MODULUS)
            m = hashlib.sha1()
            m.update(str(session_key))
            key = m.digest()[0:16]

            unverified_hop.session_key = key

            self.circuit.add_hop(unverified_hop)
            self.circuit.unverified_hop = None

            try:
                candidate_list = self.community.decrypt_candidate_list(
                    key, extended_message.candidate_list)
            except Exception as e:
                reason = "Can't decrypt candidate list!"
                logger.exception(reason)
                self.community.remove_circuit(self.circuit.circuit_id, reason)
                return

            dispersy = self.community.dispersy
            if dispersy.lan_address in candidate_list:
                del candidate_list[dispersy.lan_address]

            if dispersy.wan_address in candidate_list:
                del candidate_list[dispersy.wan_address]

            for hop in self.circuit.hops:
                if hop.address in candidate_list:
                    del candidate_list[hop.address]

            if self.circuit.state == CIRCUIT_STATE_EXTENDING:
                try:
                    self.circuit.extend_strategy.extend(candidate_list)
                except ValueError as e:
                    logger.exception("Cannot extend due to exception:")
                    reason = 'Extend error, state = %s' % self.circuit.state
                    self.community.remove_circuit(self.number, reason)

            elif self.circuit.state == CIRCUIT_STATE_READY:
                self.on_success()

            if self.community.notifier:
                from Tribler.Core.simpledefs import NTFY_ANONTUNNEL, \
                    NTFY_CREATED, NTFY_EXTENDED

                if len(self.circuit.hops) == 1:
                    self.community.notifier.notify(NTFY_ANONTUNNEL,
                                                   NTFY_CREATED, self.circuit)
                else:
                    self.community.notifier.notify(NTFY_ANONTUNNEL,
                                                   NTFY_EXTENDED, self.circuit)

        def on_success(self):
            if self.circuit.state == CIRCUIT_STATE_READY:
                logger.info("Circuit %d is ready", self.number)
                self.community.dispersy.callback.register(
                    self.community.request_cache.pop, args=(self.identifier,))

        def on_timeout(self):
            if not self.circuit.state == CIRCUIT_STATE_READY:
                reason = 'timeout on CircuitRequestCache, state = %s' % self.circuit.state
                self.community.remove_circuit(self.number, reason)

    def _create_circuit(self, first_hop, goal_hops, extend_strategy=None,
                        deferred=None):
        """ Create a new circuit, with one initial hop

        @param WalkCandidate first_hop: The first hop of our circuit, needs to
            be a candidate.
        @param int goal_hops: The number of hops the circuit should reach
        @param T <= extendstrategies.ExtendStrategy extend_strategy: The extend
            strategy used

        @rtype: Circuit
        """
        try:
            circuit_id = self._generate_circuit_id(first_hop.sock_addr)

            cache = self._request_cache.add(
                ProxyCommunity.CircuitRequestCache(self, circuit_id))

            circuit = cache.circuit = Circuit(
                circuit_id=circuit_id,
                goal_hops=goal_hops,
                candidate=first_hop,
                deferred=deferred,
                proxy=self)

            if extend_strategy:
                circuit.extend_strategy = extend_strategy
            else:
                circuit.extend_strategy = self.settings.extend_strategy(
                    self, circuit)

            pub_key = iter(first_hop.get_members()).next()._ec

            dh_secret = random.getrandbits(DIFFIE_HELLMAN_MODULUS_SIZE)
            while dh_secret >= DIFFIE_HELLMAN_MODULUS:
                dh_secret = random.getrandbits(DIFFIE_HELLMAN_MODULUS_SIZE)

            dh_first_part = pow(DIFFIE_HELLMAN_GENERATOR, dh_secret,
                                DIFFIE_HELLMAN_MODULUS)

            encrypted_dh_first_part = self.crypto.encrypt(
                pub_key, int_to_packed(dh_first_part, 2048))

            circuit.unverified_hop = Hop(first_hop.sock_addr,
                                         pub_key,
                                         dh_secret)
            logger.info(
                'Circuit %d is to be created, wants %d hops sending to %s:%d',
                circuit_id, circuit.goal_hops,
                first_hop.sock_addr[0],
                first_hop.sock_addr[1]
            )

            self.circuits[circuit_id] = circuit
            self.waiting_for[(first_hop.sock_addr, circuit_id)] = True
            self.send_message(first_hop, circuit_id, MESSAGE_CREATE,
                              CreateMessage(encrypted_dh_first_part))

            return circuit
        except Exception as e:
            logger.exception("create_circuit")

    def remove_circuit(self, circuit_id, additional_info=''):
        assert isinstance(circuit_id, (long, int)), type(circuit_id)

        if circuit_id in self.circuits:
            logger.error("Breaking circuit %d " + additional_info, circuit_id)
            circuit = self.circuits[circuit_id]

            circuit.destroy()
            del self.circuits[circuit_id]
            self.__notify("on_break_circuit", circuit)

            return True
        return False

    def remove_relay(self, relay_key, additional_info=''):
        if relay_key in self.relay_from_to:
            logger.error(
                ("Breaking relay %s:%d %d " + additional_info) % (
                    relay_key[0][0], relay_key[0][1], relay_key[1]))

            # Only remove one side of the relay, this isn't as pretty but
            # both sides have separate incoming timer, hence
            # after removing one side the other will follow.
            del self.relay_from_to[relay_key]

            if relay_key in self.session_keys:
                del self.session_keys[relay_key]

            self.__notify("on_break_relay", relay_key)
            return True
        return False

    def on_create(self, circuit_id, candidate, message):
        """
        Handle incoming CREATE message, acknowledge the CREATE request with a
        CREATED reply

        @param int circuit_id: The circuit's identifier
        @param Candidate candidate: The candidate we got a CREATE message from
        @param CreateMessage message: The message's payload
        """
        logger.info('We joined circuit %d with neighbour %s', circuit_id,
                    candidate)

        relay_key = (candidate.sock_addr, circuit_id)
        self.directions[relay_key] = ENDPOINT

        dh_secret = random.getrandbits(DIFFIE_HELLMAN_MODULUS_SIZE)
        while dh_secret >= DIFFIE_HELLMAN_MODULUS:
            dh_secret = random.getrandbits(DIFFIE_HELLMAN_MODULUS_SIZE)

        my_key = self.my_member._ec

        decrypted_dh_first_part = packed_to_int(
            self.crypto.decrypt(my_key, message.key), 2048)

        key = pow(decrypted_dh_first_part, dh_secret, DIFFIE_HELLMAN_MODULUS)

        m = hashlib.sha1()
        m.update(str(key))
        key = m.digest()[0:16]

        self.session_keys[relay_key] = key
        #logger.debug("The create message's key   : {}".format(message.key))
        #logger.debug("My diffie secret           : {}".format(self.dh_secret))
        #logger.debug("SECRET {} FOR THE ORIGINATOR NODE".format(key))

        return_key = pow(DIFFIE_HELLMAN_GENERATOR, dh_secret,
                         DIFFIE_HELLMAN_MODULUS)

        cand_dict = {}
        for i in range(1, 5):
            candidate_temp = next(self.dispersy_yield_verified_candidates(),
                                  None)
            if not candidate_temp:
                break
            # first member of candidate contains elgamal key
            ec_key = iter(candidate_temp.get_members()).next()._ec

            key_string = self.crypto.key_to_bin(ec_key)

            cand_dict[candidate_temp.sock_addr] = key_string
            logger.debug("Found candidate {0} with key".format(
                candidate_temp.sock_addr))

        if self.notifier:
            from Tribler.Core.simpledefs import NTFY_ANONTUNNEL, NTFY_JOINED

            self.notifier.notify(NTFY_ANONTUNNEL, NTFY_JOINED,
                                 candidate.sock_addr, circuit_id)

        index = (candidate.sock_addr, circuit_id)
        encrypted_cand_dict = self.encrypt_candidate_list(
            self.session_keys[index], cand_dict)

        return self.send_message(
            destination=candidate,
            circuit_id=circuit_id,
            message_type=MESSAGE_CREATED,
            message=CreatedMessage(return_key, encrypted_cand_dict)
        )

    @staticmethod
    def encrypt_candidate_list(key, cand_dict):
        encoded_dict = encoding.encode(cand_dict)
        return crypto.aes_encode(key, encoded_dict)

    @staticmethod
    def decrypt_candidate_list(key, encrypted_cand_dict):
        encoded_dict = crypto.aes_decode(key, encrypted_cand_dict)
        offset, cand_dict = encoding.decode(encoded_dict)
        return cand_dict

    def on_created(self, circuit_id, candidate, message):
        """ Handle incoming CREATED messages relay them backwards towards
        the originator if necessary

        @param int circuit_id: The circuit's id we got a CREATED message on
        @param Candidate candidate: The candidate we got the message from
        @param CreatedMessage message: The message we received

        @return: whether the message could be handled correctly

        """
        relay_key = (candidate.sock_addr, circuit_id)

        del self.waiting_for[relay_key]
        self.directions[relay_key] = ORIGINATOR
        if relay_key in self.relay_from_to:
            logger.debug("Got CREATED message, forward as EXTENDED to origin.")
            extended_message = ExtendedMessage(message.key,
                                               message.candidate_list)
            forwarding_relay = self.relay_from_to[relay_key]

            candidate = Candidate(forwarding_relay.sock_addr, False)
            return self.send_message(candidate, forwarding_relay.circuit_id,
                                     MESSAGE_EXTENDED, extended_message)

        request = self.dispersy.callback.call(
            self.request_cache.get,
            args=(self.CircuitRequestCache.create_identifier(circuit_id),))

        if request:
            request.on_extended(message)
            return True

        return False

    def on_data(self, circuit_id, candidate, message):
        """
        Handles incoming DATA message

        Determines whether the data comes from the outside world (origin set)
        or whether the data came from the origin (destination set)

        If the data comes from the outside world the on_incoming_from_tunnel
        method is called on the observers and the circuit is marked as active

        When the data comes from the origin we need to EXIT to the outside
        world. This is left to the observers as well, by calling the
        on_exiting_from_tunnel method.

        @param int circuit_id: the circuit's id we received the DATA message on
        @param Candidate|None candidate: the messenger of the packet
        @param DataMessage message: the message's content

        @return: whether the message could be handled correctly
        """

        # If its our circuit, the messenger is the candidate assigned to that
        # circuit and the DATA's destination is set to the zero-address then
        # the packet is from the outside world and addressed to us from
        if circuit_id in self.circuits and message.origin \
                and candidate == self.circuits[circuit_id].candidate:

            if __debug__:
                print "Exit socket at {0}".format(message.destination)

            self.circuits[circuit_id].beat_heart()
            self.__notify(
                "on_incoming_from_tunnel", self, self.circuits[circuit_id],
                message.origin, message.data)

            return True

        # It is not our circuit so we got it from a relay, we need to EXIT it!
        if message.destination != ('0.0.0.0', 0):
            for observer in self.__observers:
                observer.on_exiting_from_tunnel(circuit_id, candidate,
                                                message.destination,
                                                message.data)

            return True
        return False

    def on_extend(self, circuit_id, candidate, message):
        """
        Upon reception of a EXTEND message the message is forwarded over the
        Circuit if possible. At the end of the circuit a CREATE request is
        send to the Proxy to extend the circuit with. It's CREATED reply will
        eventually be received and propagated back along the Circuit.

        @param int circuit_id: the circuit's id we got the EXTEND message on
        @param Candidate candidate: the relay which sent us the EXTEND
        @param ExtendMessage message: the message's content

        @return: whether the message could be handled correctly
        """

        if message.extend_with:
            extend_with_addr = message.extend_with
            logger.warning(
                "We might be sending CREATE to unknown candidate at %s:%d!",
                message.host,
                message.port)
        else:
            extend_with_addr = next(
                (x.sock_addr for x in self.dispersy_yield_verified_candidates()
                 if x and x != candidate),
                None
            )

        if not extend_with_addr:
            return

        relay_key = (candidate.sock_addr, circuit_id)
        if relay_key in self.relay_from_to:
            current_relay = self.relay_from_to[relay_key]
            assert not current_relay.online, \
                "shouldn't be called whenever relay is online, " \
                "the extend message should have been forwarded"

            # We will just forget the attempt and try again, possible with
            # another candidate
            old_to_key = current_relay.sock_addr, current_relay.circuit_id
            del self.relay_from_to[old_to_key]
            del self.relay_from_to[relay_key]

        new_circuit_id = self._generate_circuit_id(extend_with_addr)
        to_key = (extend_with_addr, new_circuit_id)

        self.waiting_for[to_key] = True
        self.relay_from_to[to_key] = RelayRoute(circuit_id,
                                                candidate.sock_addr)
        self.relay_from_to[relay_key] = RelayRoute(new_circuit_id,
                                                   extend_with_addr)

        key = message.key

        self.directions[to_key] = ORIGINATOR
        self.directions[relay_key] = ENDPOINT

        extend_candidate = self.get_cached_candidate(extend_with_addr)
        return self.send_message(extend_candidate, new_circuit_id,
                                 MESSAGE_CREATE, CreateMessage(key))

    def on_extended(self, circuit_id, candidate, message):
        """
        A circuit has been extended, forward the acknowledgment back to the
        origin of the EXTEND. If we are the origin update our records.

        @param int circuit_id: the circuit's id we got the EXTENDED message on
        @param Candidate candidate: the relay which sent us the EXTENDED
        @param ExtendedMessage message: the message's content

        @return: whether the message could be handled correctly
        """

        request = self.dispersy.callback.call(
            self._request_cache.get,
            args=(self.CircuitRequestCache.create_identifier(circuit_id),))

        if request:
            request.on_extended(message)
            return True
        return False

    class PingRequestCache(NumberCache):

        @staticmethod
        def create_number(force_number=-1):
            return force_number \
                if force_number >= 0 \
                else NumberCache.create_number()

        @staticmethod
        def create_identifier(number, force_number=-1):
            assert isinstance(number, (int, long)), type(number)
            return u"request-cache:ping-request:%d" % (number,)

        def __init__(self, community, force_number):
            NumberCache.__init__(self, community.request_cache, force_number)
            self.community = community

        @property
        def timeout_delay(self):
            return 5.0

        @property
        def cleanup_delay(self):
            return 0.0

        def on_pong(self, message):
            self.community.dispersy.callback.register(
                self.community.request_cache.pop, args=(self.identifier,))

        def on_timeout(self):
            self.community.remove_circuit(self.number, 'RequestCache')

    def create_ping(self, candidate, circuit_id):
        """
        Creates, sends and keeps track of a PING message to given candidate on
        the specified circuit.

        @param Candidate candidate: the candidate to which we want to sent a
            ping
        @param int circuit_id: the circuit id to sent the ping over
        """
        def __do_add():
            identifier = self.PingRequestCache.create_identifier(circuit_id)
            if not self._request_cache.has(identifier):
                cache = self.PingRequestCache(self, circuit_id)
                self._request_cache.add(cache)

        self._dispersy.callback.register(__do_add)

        logger.debug("SEND PING TO CIRCUIT {0}".format(circuit_id))
        self.send_message(candidate, circuit_id, MESSAGE_PING, PingMessage())

    def on_ping(self, circuit_id, candidate, message):
        """
        Upon reception of a PING message we respond with a PONG message

        @param int circuit_id: the circuit's id we got the PING from
        @param Candidate candidate: the relay we got the PING from
        @param PingMessage message: the message's content

        @return: whether the message could be handled correctly
        """
        logger.debug("GOT PING FROM CIRCUIT {0}".format(circuit_id))
        return self.send_message(
            destination=candidate,
            circuit_id=circuit_id,
            message_type=MESSAGE_PONG,
            message=PongMessage())

    def on_pong(self, circuit_id, candidate, message):
        """
        When we receive a PONG message on our circuit we can be sure that the
        circuit is alive and well.

        @param int circuit_id: the circuit's id we got the PONG message on
        @param Candidate candidate: the relay which sent us the PONG
        @param PongMessage message: the message's content

        @return: whether the message could be handled correctly
        """

        if circuit_id not in self.circuits or \
                self.circuits[circuit_id].candidate != candidate:
            raise ValueError("We got a PONG from a stranger, ABORT ABORT")

        logger.debug("GOT PONG FROM CIRCUIT {0}".format(circuit_id))
        request = self.dispersy.callback.call(
            self._request_cache.get,
            args=(self.PingRequestCache.create_identifier(circuit_id),))

        if request:
            request.on_pong(message)
            return True
        return False

    # got introduction_request or introduction_response from candidate
    # not necessarily a new candidate
    def on_member_heartbeat(self, message, candidate):
        if not isinstance(candidate, WalkCandidate) or \
                isinstance(candidate, BootstrapCandidate):
            return

        candidate._associations.clear()
        candidate.associate(message.authentication.member)
        self._heartbeat_candidates[candidate.sock_addr] = candidate

    def _generate_circuit_id(self, neighbour=None):
        circuit_id = random.randint(1, 255000)

        # prevent collisions
        while circuit_id in self.circuits or \
                (neighbour and (neighbour, circuit_id) in self.relay_from_to):
            circuit_id = random.randint(1, 255000)

        return circuit_id

    def _filter_message(self, candidate, circuit_id, message_type, payload):
        for f in self._message_filters[message_type]:
            payload = f(candidate, circuit_id, payload)

            if not payload:
                return None

        return payload

    def remove_message_filter(self, message_type, filter_func):
        self._message_filters[message_type].remove(filter_func)

    def add_message_filter(self, message_type, filter_func):
        self._message_filters[message_type].append(filter_func)

    def send_message(self, destination, circuit_id, message_type, message):
        content = self.proxy_conversion.encode(message_type, message)

        for transformer in self.send_transformers:
            content = transformer(destination, circuit_id, message_type,
                                  content)

        return self.send_packet(destination, circuit_id, message_type, content)

    def send_packet(self, destination, circuit_id, message_type, packet,
                    relayed=False):
        assert isinstance(destination, Candidate), type(destination)
        assert isinstance(packet, str), type(packet)

        packet = self.proxy_conversion.add_circuit(packet, circuit_id)

        str_type = MESSAGE_TYPE_STRING.get(
            message_type, "unknown-type-" + str(ord(message_type)))

        logger.debug(
            "SEND %s to %s:%d over circuit %d",
            str_type,
            destination.sock_addr[0], destination.sock_addr[1],
            circuit_id)

        self.dict_inc(self.dispersy.statistics.outgoing,
                      str_type + ('-relayed' if relayed else ''), 1)

        # we need to make sure that this endpoint is thread safe
        return self.dispersy.endpoint.send(
            candidates=[destination],
            packets=[self.packet_prefix + packet])

    def dict_inc(self, statistics_dict, key, inc=1):
        self._dispersy.statistics.dict_inc(
            statistics_dict,
            u"anontunnel-" + key,
            inc)

    # CIRCUIT STUFFS
    def get_circuits(self):
        return self.circuits.values()

    @property
    def active_circuits(self):
        # Circuit is active when its state is CIRCUIT_STATE_READY
        return {circuit_id: circuit
                for circuit_id, circuit in self.circuits.items()
                if circuit.state == CIRCUIT_STATE_READY}

    def check_ready(self):
        while True:
            try:
                self.online = self.settings.select_strategy.can_select(
                    self.active_circuits)
            except:
                logger.exception("Can_select should not raise any exceptions!")
                self.online = False

            yield 1.0

    def _ping_circuits(self):
        while True:
            try:
                to_be_removed = [
                    self.remove_relay(relay_key, 'no activity')
                    for relay_key, relay in self.relay_from_to.items()
                    if relay.ping_time_remaining == 0]

                logger.info("removed %d relays", len(to_be_removed))
                assert all(to_be_removed)

                to_be_pinged = [
                    circuit for circuit in self.circuits.values()
                    if circuit.ping_time_remaining < PING_INTERVAL
                    and circuit.candidate]

                logger.info("pinging %d circuits", len(to_be_pinged))
                for circuit in to_be_pinged:
                    self.create_ping(circuit.candidate, circuit.circuit_id)
            except:
                logger.exception("Ping error")

            yield PING_INTERVAL

    def unlink_destinations(self, destinations):
        with self.lock:
            for destination in destinations:
                if destination in self.destination_circuit:
                    del self.destination_circuit[destination]

    def __select_circuit(self, ultimate_destination):
        circuit_id = self.destination_circuit.get(ultimate_destination, None)

        if circuit_id in self.active_circuits:
            return self.active_circuits[circuit_id]
        else:
            strategy = self.settings.select_strategy
            circuit_id = strategy.select(
                self.active_circuits.values()).circuit_id
            self.destination_circuit[ultimate_destination] = circuit_id

            logger.warning("SELECT circuit %d with length %d for %s:%d",
                           circuit_id,
                           self.circuits[circuit_id].goal_hops,
                           *ultimate_destination)

            return self.active_circuits[circuit_id]

    def __notify(self, method, *args, **kwargs):
        for o in self.__observers:
            func = getattr(o, method)
            func(*args, **kwargs)

    def tunnel_data_to_end(self, ultimate_destination, payload, circuit=None):
        """
        Tunnel data to the end and request an EXIT to the outside world

        @param int circuit_id: The circuit's id to tunnel data over
        @param Candidate candidate: The relay to tunnel data over
        @param (str, int) ultimate_destination: The destination outside the
            tunnel community
        @param str payload: The raw payload to send to the ultimate destination

        @return: Whether the request has been handled successfully
        """

        with self.lock:
            if not circuit:
                circuit = self.__select_circuit(ultimate_destination)

            if circuit.goal_hops == 0:
                self.__notify(
                    "on_exiting_from_tunnel",
                    circuit.circuit_id, None, ultimate_destination, payload)
            else:
                self.send_message(circuit.candidate, circuit.circuit_id,
                                  MESSAGE_DATA,
                                  DataMessage(ultimate_destination,
                                              payload, None))

                self.__notify(
                    "on_send_data",
                    circuit.circuit_id, circuit.candidate,
                    ultimate_destination, payload)

    def tunnel_data_to_origin(self, circuit_id, candidate, source_address,
                              payload, accepted_on):
        """
        Tunnel data to originator

        @param int circuit_id: The circuit's id to return data over
        @param Candidate candidate: The relay to return data over
        @param (str, int) source_address: The source outside the tunnel
            community
        @param str payload: The raw payload to return to the originator

        @return: Whether the request has been handled successfully
        """
        with self.lock:
            result = self.send_message(
                candidate, circuit_id, MESSAGE_DATA,
                DataMessage(accepted_on, payload, source_address))

            if result:
                self.__notify("on_enter_tunnel", circuit_id, candidate,
                              source_address, payload)

            return result

    def reserve_circuit(self):
        """
        Reserve a (future) circuit
        @rtype: defer.Deferred
        """

        def __reserve(circuit):
            logger.warning("Reserving circuit {0}".format(circuit.circuit_id))
            self._reservations.add(circuit)

            return circuit

        with self.lock:
            free = next((c for c in self.circuits.itervalues()
                         if c not in self._reservations), None)

            if free:
                __reserve(free)
                return free.deferred

            else:
                deferred = defer.Deferred()

                # remove from the list when circuit is ready
                deferred.addCallback(lambda circuit: __reserve(circuit))
                self._circuit_promises.append(deferred)

        return deferred

    def cancel_reservation(self, circuit):
        """
        Free a circuit from a reservation
        @param Circuit circuit: Circuit to free
        @rtype: bool
        """
        if circuit.circuit_id in self._reservations:
            with self.lock:
                self._reservations.remove(circuit)

                return True
        return False