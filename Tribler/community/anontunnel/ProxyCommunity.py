import logging

logger = logging.getLogger(__name__)

from Tribler.community.anontunnel.ProxyConversion import BreakPayload, PingPayload, PongPayload, StatsPayload

from Tribler.dispersy.candidate import BootstrapCandidate, Candidate, WalkCandidate
from Tribler.dispersy.authentication import NoAuthentication
from Tribler.dispersy.community import Community
from Tribler.dispersy.conversion import DefaultConversion
from Tribler.dispersy.destination import CandidateDestination
from Tribler.dispersy.distribution import DirectDistribution
from Tribler.dispersy.message import Message
from Tribler.dispersy.resolution import PublicResolution

from ProxyConversion import CreatePayload, ProxyConversion, ExtendedPayload, DataPayload, ExtendPayload
from Observable import Observable
import functools

class Mock(object):
    def __init__(self, **kwargs):
         self.__dict__.update(kwargs)

class ProxyCommunity(Community, Observable):

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
    def load_community(cls, dispersy, master, my_member, socks_server, create_tunnel=True):
        try:
            dispersy.database.execute(u"SELECT 1 FROM community WHERE master = ?", (master.database_id,)).next()
        except StopIteration:
            return cls.join_community(dispersy, master, my_member, my_member, socks_server)
        else:
            return super(ProxyCommunity, cls).load_community(dispersy, master, socks_server)

    def __init__(self, dispersy, master_member, onready=None):
        Observable.__init__(self)

        # original walker callbacks (will be set during super(...).__init__)
        self._original_on_introduction_request = None
        self._original_on_introduction_response = None

        Community.__init__(self, dispersy, master_member)

        dispersy.endpoint.bypass_community = self

        if onready:
            onready(self)

        # Heartbeat hashmap Candidate -> last heart beat timestamp, assume we never heard any
        self.member_heartbeat = {}
        self.member_ping = {}

        def on_pong(event, message):
            logger.debug("Got PONG from %s:%d" % (message.candidate.sock_addr[0], message.candidate.sock_addr[1]))

        self.subscribe("on_pong", on_pong)


    def initiate_conversions(self):
        ret = [DefaultConversion(self), ProxyConversion(self)]

        self.dispersy.endpoint.bypass_prefix = ret[1]._prefix + chr(5)

        return ret

    def initiate_meta_messages(self):
        def yield_all(messages):
            for msg in messages:
                yield msg

        def trigger_event(messages, event_name):
            for msg in messages:
                if msg.candidate in self.member_ping:
                    del self.member_ping[msg.candidate]

                self.fire("on_member_heartbeat", candidate=msg.candidate)
                self.fire(event_name, message=msg)

        event_messages_def = {
            u"create": CreatePayload(),
            u"created": CreatePayload(),
            u"extend": ExtendPayload(),
            u"extended": ExtendedPayload(),
            u"data": DataPayload(),
            u"break": BreakPayload(),
            u"pong": PongPayload(),
            u"ping": PingPayload(),
            u"stats": StatsPayload()
        }

        event_messages = [
            Message(self,
                message_key,
                NoAuthentication(),
                PublicResolution(),
                DirectDistribution(),
                CandidateDestination(),
                payload,
                yield_all,
                functools.partial(trigger_event, event_name="on_"+message_key))

            for message_key, payload in event_messages_def.items()
        ]

        self.subscribe("on_ping", self.on_ping)

        return event_messages

    def on_bypass_message(self, candidate, packet):
        placeholder = Mock(meta=self.get_meta_message(u"data"))
        offset, payload = ProxyConversion._decode_data(placeholder, len(self.dispersy.endpoint.bypass_prefix), packet)

        #assert payload.circuit_id == 123
        #assert payload.destination == ("8.8.8.8", 80)
        #assert payload.data == "TEST"
        #assert payload.origin == ("127.0.0.1", 1234)


        self.fire("on_data", message=Mock(payload=payload, candidate=candidate))


    def send_data(self, candidate, payload):
        #payload = Mock(circuit_id=123, destination=("8.8.8.8", 80), data="TEST", origin=("127.0.0.1", 1234))

        data = self.dispersy.endpoint.bypass_prefix + ''.join(s for s in ProxyConversion._encode_data(Mock(payload=payload)))
        self.dispersy.endpoint.send([candidate], [data])

    def _initialize_meta_messages(self):
        super(ProxyCommunity, self)._initialize_meta_messages()

        # replace the callbacks for the dispersy-introduction-request and
        # dispersy-introduction-response messages
        meta = self._meta_messages[u"dispersy-introduction-request"]
        self._original_on_introduction_request = meta.handle_callback
        self._meta_messages[meta.name] = Message(meta.community, meta.name, meta.authentication, meta.resolution,
                                                 meta.distribution, meta.destination, meta.payload, meta.check_callback,
                                                 self.on_introduction_request, meta.undo_callback, meta.batch)
        assert self._original_on_introduction_request

        meta = self._meta_messages[u"dispersy-introduction-response"]
        self._original_on_introduction_response = meta.handle_callback
        self._meta_messages[meta.name] = Message(meta.community, meta.name, meta.authentication, meta.resolution,
                                                 meta.distribution, meta.destination, meta.payload, meta.check_callback,
                                                 self.on_introduction_response, meta.undo_callback, meta.batch)
        assert self._original_on_introduction_response

    def send(self, message_type, destination_candidate, *payload):
        assert isinstance(destination_candidate, Candidate), "destination_candidate should be a Candidate"

        meta = self.get_meta_message(message_type)
        message = meta.impl(distribution=(self.global_time,), payload=payload)

        self.dispersy.endpoint.send([destination_candidate], [message.packet])

    def on_ping(self, event, message):
        logger.debug("Got PING from %s:%d" % (message.candidate.sock_addr[0], message.candidate.sock_addr[1]))
        self.send(u"pong", message.candidate, message.payload.circuit_id)

    def on_introduction_request(self, messages):
        try:
            return self._original_on_introduction_request(messages)
        finally:
            for message in messages:
                if not isinstance(message.candidate, BootstrapCandidate) and isinstance(message.candidate, WalkCandidate):
                    self.fire("on_member_heartbeat", candidate=message.candidate)

    def on_introduction_response(self, messages):
        try:
            return self._original_on_introduction_response(messages)
        finally:
            for message in messages:
                if not isinstance(message.candidate, BootstrapCandidate) and isinstance(message.candidate, WalkCandidate):
                    self.fire("on_member_heartbeat", candidate=message.candidate)

    def on_candidate_exit(self, candidate):
        if candidate in self.member_ping:
            del self.member_ping[candidate]

        if candidate in self.member_heartbeat:
            del self.member_heartbeat[candidate]

        try:
            self.fire("on_member_exit", member=candidate)
        except:
            logger.error("Error caught in on_member_exit callback")
