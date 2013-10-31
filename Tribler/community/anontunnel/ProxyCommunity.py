from collections import defaultdict
from datetime import datetime, timedelta
import logging
logger = logging.getLogger(__name__)

from Tribler.community.anontunnel.ProxyConversion import BreakPayload, PingPayload, PongPayload, StatsPayload
from Tribler.community.anontunnel.DispersyTunnelProxy import DispersyTunnelProxy
from Tribler.community.anontunnel.TriblerNotifier import TriblerNotifier

from Tribler.dispersy.candidate import BootstrapCandidate, Candidate
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

        if onready:
            onready(self)

        # Heartbeat hashmap Candidate -> last heart beat timestamp, assume we never heard any
        self.member_heartbeat = {}
        self.member_ping = {}

        def on_pong(event, message):
            logger.debug("Got PONG from %s:%d" % (message.candidate.sock_addr[0], message.candidate.sock_addr[1]))

        self.subscribe("on_pong", on_pong)

        def ping_and_purge():
            while True:
                logger.info("ping_purge")

                try:
                    timeout = 2.0

                    # Candidates we have sent a ping in the last 'time out' seconds and haven't returned a heat beat
                    # in 2*timeout seconds shall be purged
                    candidates_to_be_purged = \
                        {
                            candidate
                            for candidate in self.member_heartbeat.keys()
                            if self.member_heartbeat[candidate] < datetime.now() - timedelta(seconds=4*timeout)
                        }

                    for candidate in candidates_to_be_purged:
                        self.on_candidate_exit(candidate)
                        logger.error("CANDIDATE exit %s:%d" % (candidate.sock_addr[0], candidate.sock_addr[1]))


                    candidates_to_be_pinged = {candidate for candidate in self.member_heartbeat.keys() if
                                               self.member_heartbeat[candidate] < datetime.now() - timedelta(
                                                   seconds=timeout)}

                    for candidate in candidates_to_be_pinged:
                        self.member_ping[candidate] = datetime.now()
                        self.send(u"ping", candidate)
                        logger.debug("PING sent to %s:%d" % (candidate.sock_addr[0], candidate.sock_addr[1]))


                except:
                    pass

                # rerun over 3 seconds
                yield 2.0

        self.dispersy.callback.register(ping_and_purge, priority= 0)


    def initiate_conversions(self):
        return [DefaultConversion(self), ProxyConversion(self)]

    def initiate_meta_messages(self):
        def yield_all(messages):
            for msg in messages:
                yield msg

        def trigger_event(messages, event_name):
            for msg in messages:
                if msg.candidate in self.member_ping:
                    del self.member_ping[msg.candidate]

                self.member_heartbeat[msg.candidate] = datetime.now()
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
        self.send(u"pong", message.candidate)

    def on_introduction_request(self, messages):
        try:
            return self._original_on_introduction_request(messages)
        finally:
            for message in messages:
                if not isinstance(message.candidate, BootstrapCandidate):
                    self.fire("on_member_heartbeat", candidate=message.candidate)

    def on_introduction_response(self, messages):
        try:
            return self._original_on_introduction_response(messages)
        finally:
            for message in messages:
                if not isinstance(message.candidate, BootstrapCandidate):
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
