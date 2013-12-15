import logging
logger = logging.getLogger(__name__)

from Tribler.community.anontunnel.globals import *
from Crypto.Random.random import randint
from Tribler.community.anontunnel import ExtendStrategies
from Tribler.community.anontunnel.CircuitLengthStrategies import ConstantCircuitLengthStrategy
from Tribler.community.anontunnel.SelectionStrategies import RandomSelectionStrategy
from traceback import print_exc
from Tribler.dispersy.dispersy import IntroductionRequestCache

from time import time

from Tribler.community.anontunnel.conversion import ProxyConversion,\
    CustomProxyConversion
from Tribler.community.anontunnel.payload import StatsPayload, CreatedMessage,\
    PongMessage, CreateMessage, ExtendedWithMessage, PingMessage

from Tribler.dispersy.candidate import BootstrapCandidate, WalkCandidate,\
    Candidate
from Tribler.dispersy.authentication import MemberAuthentication
from Tribler.dispersy.community import Community
from Tribler.dispersy.conversion import DefaultConversion
from Tribler.dispersy.destination import CommunityDestination
from Tribler.dispersy.distribution import LastSyncDistribution
from Tribler.dispersy.message import Message
from Tribler.dispersy.resolution import PublicResolution

class Circuit:
    """ Circuit data structure storing the id, status, first hop and all hops """
    
    def __init__(self, community, circuit_id, goal_hops=0, candidate=None):
        """
        Instantiate a new Circuit data structure

        :param circuit_id: the id of the candidate circuit
        :param candidate: the first hop of the circuit
        :return: Circuit
        """

        self.community = community
        self.circuit_id = circuit_id
        self.candidate = candidate
        self.hops = [candidate.sock_addr] if candidate else []
        self.goal_hops = goal_hops

        self.extend_strategy = None
        self.timestamp = None
        self.times = []
        self.bytes_up_list = []
        self.bytes_down_list = []

        self.bytes_down = [0, 0]
        self.bytes_up = [0, 0]

        self.speed_up = 0.0
        self.speed_down = 0.0
        self.last_incomming = time()
    
    @property
    def bytes_downloaded(self):
        return self.bytes_down[1]

    @property
    def bytes_uploaded(self):
        return self.bytes_up[1]

    @property
    def online(self):
        return self.goal_hops == len(self.hops)
    
    @property
    def state(self):
        if self.hops == None:
            return CIRCUIT_STATE_BROKEN
        
        if len(self.hops) < self.goal_hops:
            return CIRCUIT_STATE_EXTENDING
        else:
            return CIRCUIT_STATE_READY
        
    @property
    def ping_time_remaining(self):
        too_old = time() - CANDIDATE_WALK_LIFETIME - 5.0
        diff = self.last_incomming - too_old
        return diff if diff > 0 else 0
            
    def __contains__(self, other):
        if isinstance(other, Candidate):
            #TODO: should compare to a list here
            return other == self.candidate

class RelayRoute(object):
    def __init__(self, circuit_id, candidate):
        self.candidate = candidate
        self.circuit_id = circuit_id

        self.timestamp = None

        self.times = []
        self.bytes_list = []
        self.bytes = [0, 0]
        self.speed = 0

        self.online = False

        self.last_incomming = time()
        
    @property
    def ping_time_remaining(self):
        too_old = time() - CANDIDATE_WALK_LIFETIME - 5.0
        diff = self.last_incomming - too_old
        return diff if diff > 0 else 0

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
        master_key = "3081a7301006072a8648ce3d020106052b8104002703819200040460829f9bb72f0cb094904aa6f885ff70e1e98651e81119b1e7b42402f3c5cfa183d8d96738c40ffd909a70020488e3b59b67de57bb1ac5dec351d172fe692555898ac944b68c730590f850ab931c5732d5a9d573a7fe1f9dc8a9201bc3cb63ab182c9e485d08ff4ac294f09e16d3925930946f87e91ef9c40bbb4189f9c5af6696f57eec3b8f2f77e7ab56fd8d6d63".decode("HEX")
        master = dispersy.get_member(master_key)
        return [master]

    @classmethod
    def load_community(cls, dispersy, master, my_member, integrate_with_tribler=True):
        try:
            dispersy.database.execute(u"SELECT 1 FROM community WHERE master = ?", (master.database_id,)).next()
        except StopIteration:
            return cls.join_community(dispersy, master, my_member, my_member, integrate_with_tribler=integrate_with_tribler)
        else:
            return super(ProxyCommunity, cls).load_community(dispersy, master, integrate_with_tribler=integrate_with_tribler)

    def __init__(self, dispersy, master_member, length = None, integrate_with_tribler=True):
        Community.__init__(self, dispersy, master_member)

        # Custom conversion
        self.prefix = 'f' * 22 + 'e' #shouldn't this be "fffffffe".decode("HEX")?
        self.proxy_conversion = CustomProxyConversion(self.prefix)
        self.on_custom = {}
        self.on_custom[MESSAGE_BREAK] = self.on_break
        self.on_custom[MESSAGE_CREATE] = self.on_create
        self.on_custom[MESSAGE_CREATED] = self.on_created
        self.on_custom[MESSAGE_DATA] = self.on_data
        self.on_custom[MESSAGE_EXTEND] = self.on_extend
        self.on_custom[MESSAGE_EXTENDED] = self.on_extended
        self.on_custom[MESSAGE_PING] = self.on_ping
        self.on_custom[MESSAGE_PONG] = self.on_pong
        self.on_custom[MESSAGE_PUNCTURE] = self.on_puncture
        
        # Replace endpoint
        dispersy.endpoint.bypass_prefix = self.prefix
        dispersy.endpoint.bypass_community = self
        
        self.circuits = {}
        self.relay_from_to = {}
        
        # Stats
        self.stats = {
            'bytes_enter': 0,
            'bytes_exit': 0,
            'bytes_returned': 0,
            'dropped_exit': 0,
            'packet_size': 0
        }
        
        if length == None:
            length = randint(0, 4)
        if length == 0:
            # Add 0-hop circuit
            self.circuits[0] = Circuit(self, 0)
        
        self.circuit_length_strategy = ConstantCircuitLengthStrategy(length)
        self.circuit_selection_strategy = RandomSelectionStrategy(1)
        self.extend_strategy = ExtendStrategies.TrustThyNeighbour
        
        # Heartbeat hashmap Candidate -> last heart beat timestamp, assume we never heard any
        self.member_heartbeat = {}
        self.member_ping = {}
        
        self.online = False
        dispersy._callback.register(self.check_ready)
        dispersy._callback.register(self.ping_circuits)
        
        if integrate_with_tribler:
            from Tribler.Core.CacheDB.Notifier import Notifier
            self.notifier = Notifier.getInstance()
        else:
            self.notifier = None 

    def initiate_conversions(self):
        return [DefaultConversion(self), ProxyConversion(self)]

    def initiate_meta_messages(self):
        return [Message(
            self
            , u"stats"
            , MemberAuthentication()
            , PublicResolution()
            , LastSyncDistribution(synchronization_direction=u"DESC", priority=128, history_size=1)
            , CommunityDestination(node_count=10)
            , StatsPayload()
            , self._dispersy._generic_timeline_check
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
        self._meta_messages[meta.name] = Message(meta.community, meta.name, meta.authentication, meta.resolution,
                                                 meta.distribution, meta.destination, meta.payload, meta.check_callback,
                                                 self.on_introduction_request, meta.undo_callback, meta.batch)

        meta = self._meta_messages[u"dispersy-introduction-response"]
        self._original_on_introduction_response = meta.handle_callback
        self._meta_messages[meta.name] = Message(meta.community, meta.name, meta.authentication, meta.resolution,
                                                 meta.distribution, meta.destination, meta.payload, meta.check_callback,
                                                 self.on_introduction_response, meta.undo_callback, meta.batch)
        
        assert self._original_on_introduction_request
        assert self._original_on_introduction_response
        
    def on_introduction_request(self, messages):
        try:
            return self._original_on_introduction_request(messages)
        finally:
            for message in messages:
                self.on_member_heartbeat(message.candidate)

    def on_introduction_response(self, messages):
        try:
            return self._original_on_introduction_response(messages)
        finally:
            for message in messages:
                self.on_member_heartbeat(message.candidate)
                    
    def on_stats(self, messages):
        for message in messages:
            #TODO: call callback?
            pass
        
    def send_stats(self, stats):
        meta = self.get_meta_message(u"stats")
        record = meta.impl(authentication=(self._my_member,),
                           distribution=(self.claim_global_time(),),
                           payload=(stats,))

        self.dispersy.store_update_forward([record], True, False, True)
        
    ### END OF DISPERSY DEFINED MESSAGES
    ### START OF CUSTOM MESSAGES

    def on_bypass_message(self, sock_addr, packet):
        dispersy = self._dispersy
        
        #TODO: we should attempt to get the candidate from the member_heartbeat dict
        #get_candidate has a garbage collector :P
        candidate = self.get_candidate(sock_addr) or Candidate(sock_addr, False)
        circuit_id, data = self.proxy_conversion.get_circuit_and_data(packet)
        relay_key = (candidate, circuit_id)
        packet_type = self.proxy_conversion.get_type(data)
        
        logger.debug("GOT %s from %s:%d over circuit %d", MESSAGE_STRING_REPRESENTATION[packet_type], candidate.sock_addr[0], candidate.sock_addr[1], circuit_id)
        
        # First reset last_incomming timestamp of circuit
        # TODO: why only reset the last_incomming for ready circuits?
        if circuit_id in self.circuits and self.circuits[circuit_id].state == CIRCUIT_STATE_READY:
            self.circuits[circuit_id].last_incomming = time()
            
        # Next, relay packet if we know whom to forward message to for this circuit
        if circuit_id > 0 and relay_key in self.relay_from_to and self.relay_from_to[relay_key].online:
            next_relay = self.relay_from_to[relay_key]
            new_packet = self.prefix + self.proxy_conversion.add_circuit(data, next_relay.circuit_id)
            #TODO: this is not true, its an outgoing packet
            next_relay.last_incomming = time()
            next_relay.bytes[1] += len(new_packet)
            
            self.send_packet(next_relay.candidate, circuit_id, packet_type, new_packet, relayed=True)
            
            #hmm, are we able to read this message type if we're relaying
            #moreover, shouldn't we be calling self.break_circuit
            if packet_type == MESSAGE_BREAK:
                # Route is dead :(
                logging.DEBUG('routing is dead')
                del self.relay_from_to[relay_key]
                
            self.dict_inc(dispersy.statistics.success, MESSAGE_STRING_REPRESENTATION[packet_type] + '-relayed')
        
        # We don't know where to relay this message to, must be for me?
        else:
            type, payload = self.proxy_conversion.decode(data)
            # TODO: I think this can be removed if we remove the initial additional constraint
            if circuit_id in self.circuits:
                self.circuits[circuit_id].last_incomming = time()
            
            if not self.on_custom[type](circuit_id, candidate, payload):
                self.dict_inc(dispersy.statistics.success, MESSAGE_STRING_REPRESENTATION[packet_type] + '-ignored')
                logger.debug("Prev message was IGNORED")
            else:
                self.dict_inc(dispersy.statistics.success, MESSAGE_STRING_REPRESENTATION[packet_type])
    
    def on_break(self, circuit_id, candidate, message):
        self._break_circuit(circuit_id)
        
    def _break_circuit(self, circuit_id, additional_info = ''):
        assert isinstance(circuit_id, (long, int)), type(circuit_id)
        
        if circuit_id in self.circuits:
            logger.info("Breaking circuit %d " +additional_info, circuit_id)

            # Delete from data structures
            if self.circuits[circuit_id].extend_strategy:
                self.circuits[circuit_id].extend_strategy.stop()
            del self.circuits[circuit_id]

            return True
        return False
    
    class CircuitRequestCache(IntroductionRequestCache):
        @staticmethod
        def create_identifier(number):
            assert isinstance(number, (int, long)), type(number)
            return u"request-cache:circuit-request:%d" % (number,)
        
        def __init__(self, community):
            IntroductionRequestCache.__init__(self, community, None)

        @property
        def cleanup_delay(self):
            return 0.0

        def on_created(self):
            if self.circuit.state == CIRCUIT_STATE_EXTENDING:
                self.circuit.extend_strategy.extend()
            elif self.circuit.state == CIRCUIT_STATE_READY:
                self.on_success()
        
            if self.community.notifier:
                from Tribler.Core.simpledefs import NTFY_ANONTUNNEL, NTFY_CREATED
                self.community.notifier.notify(NTFY_ANONTUNNEL, NTFY_CREATED, self.circuit)
            
        def on_extended(self, extended_message):
            self.circuit.hops.append(extended_message.extended_with)
        
            if self.circuit.state == CIRCUIT_STATE_EXTENDING:
                self.circuit.extend_strategy.extend()
                
            elif self.circuit.state == CIRCUIT_STATE_READY:
                self.on_success()
                
            if self.community.notifier:
                from Tribler.Core.simpledefs import NTFY_ANONTUNNEL, NTFY_EXTENDED
                self.community.notifier.notify(NTFY_ANONTUNNEL, NTFY_EXTENDED, self.circuit)
                
        def on_success(self):
            if self.circuit.state == CIRCUIT_STATE_READY:
                logger.debug("Circuit %d is ready", self.number)
                self.community._dispersy._callback.register(self.community._request_cache.pop, args = (self.identifier,))

        def on_timeout(self):
            if not self.circuit.state == CIRCUIT_STATE_READY:
                self.community._break_circuit(self.number, 'timeout on CircuitRequestCache, state = %s'%self.circuit.state)

    def create_circuit(self, first_hop_candidate, extend_strategy=None):
        """ Create a new circuit, with one initial hop """
        
        cache = self._request_cache.add(ProxyCommunity.CircuitRequestCache(self))

        goal_hops = self.circuit_length_strategy.circuit_length()
        circuit = cache.circuit = Circuit(self, cache.number, goal_hops, first_hop_candidate)
        circuit.extend_strategy = extend_strategy(self, circuit) if extend_strategy else self.extend_strategy(self, circuit)
        self.circuits[circuit.circuit_id] = circuit
        
        logger.info('Circuit %d is to be created, we want %d hops sending to %s:%d', circuit.circuit_id, circuit.goal_hops, first_hop_candidate.sock_addr[0], first_hop_candidate.sock_addr[1])
        self.send_message(first_hop_candidate, circuit.circuit_id, MESSAGE_CREATE, CreateMessage())
        return circuit

    def on_create(self, circuit_id, candidate, message):
        """ Handle incoming CREATE message, acknowledge the CREATE request with a CREATED reply """
        logger.info('We joined circuit %d with neighbour %s', circuit_id, candidate)
        
        if self.notifier:
            from Tribler.Core.simpledefs import NTFY_ANONTUNNEL, NTFY_JOINED
            self.notifier.notify(NTFY_ANONTUNNEL, NTFY_JOINED, candidate.sock_addr, circuit_id)

        return self.send_message(candidate, circuit_id, MESSAGE_CREATED, CreatedMessage()) 

    def on_created(self, circuit_id, candidate, message):
        """ Handle incoming CREATED messages relay them backwards towards the originator if necessary """
        request = self._dispersy._callback.call(self._request_cache.get, args = (ProxyCommunity.CircuitRequestCache.create_identifier(circuit_id),))
        if request:
            request.on_created()
            return True
        
        relay_key = (candidate, circuit_id)
        if relay_key in self.relay_from_to:
            created_to = candidate
            created_for = self.relay_from_to[(created_to, circuit_id)]
            
            # Mark link online such that no new extension attempts will be taken
            created_for.online = True
            self.relay_from_to[(created_for.candidate, created_for.circuit_id)].online = True
            
            self.send_message(created_for.candidate, created_for.circuit_id, MESSAGE_EXTENDED,
                              ExtendedWithMessage(created_to.sock_addr))

            logger.info('We have created a circuit requested by (%s, %d) to (%s,%d)',
                           created_for.candidate,
                           created_for.circuit_id,
                           created_to,
                           circuit_id
            )
            
            return True
        return False

    def on_data(self, circuit_id, candidate, message):
        """ Handles incoming DATA message, forwards it over the chain or over the internet if needed."""
        #TODO: what's happening here?, some magic averaging I guess
        self.stats['packet_size'] = 0.8 * self.stats['packet_size'] + 0.2 * len(message.data)

        if circuit_id in self.circuits \
            and message.destination == ("0.0.0.0", 0) \
            and candidate == self.circuits[circuit_id].candidate:
            
            self.circuits[circuit_id].last_incomming = time()
            self.circuits[circuit_id].bytes_down[1] += len(message.data)
            self.stats['bytes_returned'] += len(message.data)
            
            return True

        # If it is not ours and we have nowhere to forward to then act as exit node
        if message.destination != ('0.0.0.0', 0):
            self.exit_data(circuit_id, candidate, message.destination, message.data)
            
            return True
        return False
        
    def on_extend(self, circuit_id, candidate, message):
        """ Upon reception of a EXTEND message the message
            is forwarded over the Circuit if possible. At the end of
            the circuit a CREATE request is send to the Proxy to
            extend the circuit with. It's CREATED reply will
            eventually be received and propagated back along the Circuit. """

        if message.extend_with:
            extend_with = self.get_candidate(message.extend_with) or Candidate(message.extend_with, False)
            logger.warning("We might be sending a CREATE to someone we don't know, sending to %s:%d!", message.host, message.port)
        else:
            extend_with = next(
                (x for x in self.dispersy_yield_verified_candidates()
                 if x and x != candidate),
                None
            )
        
        relay_key = (candidate, circuit_id)
        if relay_key in self.relay_from_to:
            current_relay = self.relay_from_to[relay_key]
            assert not current_relay.online, "shouldn't be called whenever relay is online, the extend message should have been forwarded" 
            
            # We will just forget the attempt and try again, possible with another candidate
            old_to_key = current_relay.candidate, current_relay.circuit_id
            del self.relay_from_to[old_to_key]
            del self.relay_from_to[relay_key]

        new_circuit_id = self._generate_circuit_id(extend_with)
        to_key = (extend_with, new_circuit_id)

        self.relay_from_to[to_key] = RelayRoute(circuit_id, candidate)
        self.relay_from_to[relay_key] = RelayRoute(new_circuit_id, extend_with)

        return self.send_message(extend_with, new_circuit_id, MESSAGE_CREATE, CreateMessage())
    
    def on_extended(self, circuit_id, candidate, message):
        """ A circuit has been extended, forward the acknowledgment back
            to the origin of the EXTEND. If we are the origin update
            our records. """

        request = self._dispersy._callback.call(self._request_cache.get, args = (ProxyCommunity.CircuitRequestCache.create_identifier(circuit_id),))
        if request:
            request.on_extended(message)
            return True
        
        return False
        
    def create_ping(self, candidates, circuit_ids):
        #TODO: this needs to be upgraded to use the pingrequestcache
        logger.info("pinging %d circuits/relays", len(candidates))
        for candidate, circuit_id in zip(candidates, circuit_ids):
            self.send_message(candidate, circuit_id, MESSAGE_PING, PingMessage())
    
    def on_ping(self, circuit_id, candidate, message):
        if circuit_id in self.circuits:
            return self.send_message(candidate, circuit_id, MESSAGE_PONG, PongMessage())
        return False
        
    def on_pong(self, circuit_id, candidate, message):
        return True
        
    def on_puncture(self, circuit_id, candidate, message):
        introduce = Candidate(message.sock_addr, False)
        logger.debug("We are puncturing our NAT to %s:%d" % introduce.sock_addr)
        
        meta_puncture_request = self.get_meta_message(u"dispersy-puncture-request")
        puncture_message = meta_puncture_request.impl(distribution=(self.global_time,),
                                                      destination=(introduce,), payload=(
                                                      message.sock_addr, message.sock_addr, randint(0, 2 ** 16)))

        return self.dispersy.endpoint.send([introduce], [puncture_message.packet])
        
    
    #got introduction_request or introduction_response from candidate
    #not necessarily a new candidate
    def on_member_heartbeat(self, candidate):
        assert isinstance(candidate, WalkCandidate), type(candidate)
        if not isinstance(candidate, BootstrapCandidate):
            
            if len(self.circuits) < MAX_CIRCUITS_TO_CREATE and candidate not in self.circuits.values():
                self.create_circuit(candidate)
    
    def _generate_circuit_id(self, neighbour):
        #TODO: why is the circuit_id so small? The conversion is using a unsigned long.
        circuit_id = randint(1, 255)

        # prevent collisions
        while circuit_id in self.circuits or (neighbour, circuit_id) in self.relay_from_to:
            circuit_id = randint(1, 255)

        return circuit_id
    
    def send_message(self, destination, circuit_id, message_type, message):
        return self.send_packet(destination, circuit_id, message_type, self.proxy_conversion.encode(circuit_id, message_type, message))
        
    def send_packet(self, destination, circuit_id, message_type, packet, relayed = False):
        assert isinstance(destination, Candidate), type(destination)
        assert isinstance(packet, str), type(packet)
        assert packet.startswith(self.prefix)

        logger.debug("SEND %s to %s:%d over circuit %d", MESSAGE_STRING_REPRESENTATION[message_type], destination.sock_addr[0], destination.sock_addr[1], circuit_id)

        self.dict_inc(self.dispersy.statistics.outgoing, MESSAGE_STRING_REPRESENTATION[message_type] + ('-relayed' if relayed else ''), 1)
        
        # we need to make sure that this endpoint is threadsafe
        return self.dispersy.endpoint.send([destination], [packet])

    def dict_inc(self, statistics_dict, key, inc=1):
        self.dispersy._callback.register(self._dispersy.statistics.dict_inc, args= (statistics_dict, u"anontunnel-" + key, inc))
        
    ### CIRCUIT STUFFS
    def get_circuits(self):
        return self.circuits.values()
    
    @property
    def active_circuits(self):
        # Circuit is active when it has received a CREATED for it and the final length and the length is 0
        return [circuit for circuit in self.circuits.values() if circuit.state == CIRCUIT_STATE_READY]
        
    def check_ready(self):
        while True:
            try:
                self.circuit_selection_strategy.try_select(self.active_circuits)
                self.online = True
                
            except BaseException:
                self.online = False
                
            finally:
                yield 1.0
                
    def ping_circuits(self):
        while True:
            try:
                to_be_removed = [self._break_circuit(circuit.circuit_id, 'did not respond to ping') for circuit in self.circuits.values() if circuit.ping_time_remaining == 0]
                assert all(to_be_removed)
                
                to_be_pinged = [circuit for circuit in self.circuits.values() if circuit.ping_time_remaining < PING_INTERVAL]
                to_be_pinged += [relay for relay in self.relay_from_to.values() if relay.ping_time_remaining < PING_INTERVAL]
                
                ping_candidates = [obj.candidate for obj in to_be_pinged if obj.candidate]
                ping_ids = [obj.circuit_id for obj in to_be_pinged if obj.candidate]
                self.create_ping(ping_candidates, ping_ids)
            except:
                print_exc()

            yield PING_INTERVAL