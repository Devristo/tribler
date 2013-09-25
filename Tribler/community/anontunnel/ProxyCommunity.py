from collections import defaultdict
from datetime import datetime, timedelta
import logging
from traceback import print_exc
from Tribler.community.anontunnel.ProxyConversion import BreakPayload, PingPayload, PongPayload
from Tribler.community.anontunnel.DispersyTunnelProxy import DispersyTunnelProxy
from Tribler.community.anontunnel.TriblerNotifier import TriblerNotifier

logger = logging.getLogger(__name__)

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
    def load_community(cls, dispersy, master, my_member, socks_server):
        try:
            dispersy.database.execute(u"SELECT 1 FROM community WHERE master = ?", (master.database_id,)).next()
        except StopIteration:
            return cls.join_community(dispersy, master, my_member, my_member, socks_server)
        else:
            return super(ProxyCommunity, cls).load_community(dispersy, master, socks_server)

    def __init__(self, dispersy, master_member, socks_server):
        Observable.__init__(self)

        # original walker callbacks (will be set during super(...).__init__)
        self._original_on_introduction_request = None
        self._original_on_introduction_response = None

        Community.__init__(self, dispersy, master_member)

        self.socks_server = socks_server
        self.socks_server.tunnel = DispersyTunnelProxy(self.dispersy, self)

        self.tribler_notifier = TriblerNotifier(self.socks_server.tunnel)

        # Heartbeat hashmap Candidate -> last heart beat timestamp, assume we never heard any
        self.member_heartbeat = defaultdict(lambda: datetime.min)
        self.member_ping = defaultdict(lambda: datetime.min)

        self.subscribe("on_pong", lambda (event): logger.debug(
            "Got PONG from %s:%d" % (event.message.candidate.sock_addr[0], event.message.candidate.sock_addr[1])))

        def ping_and_purge():
            try:
                while True:
                    timeout = 2.0

                    # Candidates we have sent a ping in the last timout seconds and haven't returned a heat beat
                    # in 2*timeout seconds shall be purged
                    candidates_to_be_purged = \
                        {
                            candidate
                            for candidate in self.member_ping.keys()
                            if self.member_heartbeat[candidate] < datetime.now() - 2 * timedelta(seconds=timeout)
                        }

                    for candidate in candidates_to_be_purged:
                        self.on_candidate_exit(candidate)
                        logger.error("CANDIDATE exit %s:%d" % (candidate.sock_addr[0], candidate.sock_addr[1]))

                    candidates_to_be_pinged = {candidate for candidate in self.member_heartbeat.keys() if
                                               self.member_heartbeat[candidate] < datetime.now() - timedelta(
                                                   seconds=timeout)}.difference(candidates_to_be_purged)

                    for candidate in candidates_to_be_pinged:
                        self.send(u"ping", candidate.sock_addr)
                        logger.debug("PING sent to %s:%d" % (candidate.sock_addr[0], candidate.sock_addr[1]))

                    # rerun over 3 seconds
                    yield 3.0
            except Exception, e:
                print_exc()
                logger.error(e)

        self.dispersy.callback.register(ping_and_purge, priority= -10)


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

        return [
            Message(self,
                    u"ping",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    PingPayload(),
                    yield_all,
                    self.on_ping),

            Message(self,
                    u"pong",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    PongPayload(),
                    yield_all,
                    functools.partial(trigger_event, event_name="on_pong")),

            Message(self,
                    u"create",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    CreatePayload(),
                    yield_all,
                    functools.partial(trigger_event, event_name="on_create")),

            Message(self,
                    u"created",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    CreatePayload(),
                    yield_all,
                    functools.partial(trigger_event, event_name="on_created")),

            Message(self,
                    u"extend",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    ExtendPayload(),
                    yield_all,
                    functools.partial(trigger_event, event_name="on_extend")),

            Message(self,
                    u"extended",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    ExtendedPayload(),
                    yield_all,
                    functools.partial(trigger_event, event_name="on_extended")),

            Message(self,
                    u"data",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    DataPayload(),
                    yield_all,
                    functools.partial(trigger_event, event_name="on_data")),

            Message(self,
                    u"break",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    BreakPayload(),
                    yield_all,
                    functools.partial(trigger_event, event_name="on_break")),
        ]

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

    def send(self, message_type, destination, *payload):
        if not isinstance(destination, Candidate):
            candidate = self.get_candidate(destination)
        else:
            candidate = destination

        if not isinstance(candidate, Candidate):
            return

        meta = self.get_meta_message(message_type)
        message = meta.impl(distribution=(self.global_time,), payload=payload)

        self.dispersy.endpoint.send([candidate], [message.packet])

    def on_ping(self, messages):
        for message in messages:
            logger.debug("Got PING from %s:%d" % (message.candidate.sock_addr[0], message.candidate.sock_addr[1]))
            self.send(u"pong", message.candidate.sock_addr)

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

        self.fire("on_member_exit", member=candidate)
