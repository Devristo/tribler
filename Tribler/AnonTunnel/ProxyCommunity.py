import logging
logger = logging.getLogger(__name__)

from Tribler.dispersy.candidate import BootstrapCandidate, Candidate

from Tribler.dispersy.authentication import MemberAuthentication
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
    def __init__(self, dispersy, master_member):
        Observable.__init__(self)
        
        # original walker callbacks (will be set during super(...).__init__)
        self._original_on_introduction_request = None
        self._original_on_introduction_response = None
        
        Community.__init__(self, dispersy, master_member)

    def initiate_conversions(self):
        return [DefaultConversion(self), ProxyConversion(self)]

    def initiate_meta_messages(self):
        def yield_all(messages):
            for msg in messages:
                yield msg
                
        def trigger_event(messages,event_name):
            for msg in messages:
                self.fire(event_name, message=msg)
            
        return [Message(self,
                        u"create",
                        MemberAuthentication(encoding="sha1"),
                        PublicResolution(),
                        DirectDistribution(),
                        CandidateDestination(),
                        CreatePayload(),
                        yield_all,
                        functools.partial(trigger_event, event_name="on_create")),
                
                Message(self,
                        u"created",
                        MemberAuthentication(encoding="sha1"),
                        PublicResolution(),
                        DirectDistribution(),
                        CandidateDestination(),
                        CreatePayload(),
                        yield_all,
                        functools.partial(trigger_event, event_name="on_created")),
                
                Message(self,
                        u"extend",
                        MemberAuthentication(encoding="sha1"),
                        PublicResolution(),
                        DirectDistribution(),
                        CandidateDestination(),
                        ExtendPayload(),
                        yield_all,
                        functools.partial(trigger_event, event_name="on_extend")),
                
                Message(self,
                        u"extended",
                        MemberAuthentication(encoding="sha1"),
                        PublicResolution(),
                        DirectDistribution(),
                        CandidateDestination(),
                        ExtendedPayload(),
                        yield_all,
                        functools.partial(trigger_event, event_name="on_extended")),
                
                Message(self,
                        u"data",
                        MemberAuthentication(encoding="sha1"),
                        PublicResolution(),
                        DirectDistribution(),
                        CandidateDestination(),
                        DataPayload(),
                        yield_all,
                        functools.partial(trigger_event, event_name="on_data")),
                ]
        
    def _initialize_meta_messages(self):
        super(ProxyCommunity, self)._initialize_meta_messages()

        # replace the callbacks for the dispersy-introduction-request and
        # dispersy-introduction-response messages
        meta = self._meta_messages[u"dispersy-introduction-request"]
        self._original_on_introduction_request = meta.handle_callback
        self._meta_messages[meta.name] = Message(meta.community, meta.name, meta.authentication, meta.resolution, meta.distribution, meta.destination, meta.payload, meta.check_callback, self.on_introduction_request, meta.undo_callback, meta.batch)
        assert self._original_on_introduction_request

        meta = self._meta_messages[u"dispersy-introduction-response"]
        self._original_on_introduction_response = meta.handle_callback
        self._meta_messages[meta.name] = Message(meta.community, meta.name, meta.authentication, meta.resolution, meta.distribution, meta.destination, meta.payload, meta.check_callback, self.on_introduction_response, meta.undo_callback, meta.batch)
        assert self._original_on_introduction_response

    def send_create(self, destination, circ_id):
        candidate = self.dispersy.get_candidate(destination)
        
        meta = self.get_meta_message(u"create")
        message = meta.impl(authentication=(self.my_member,),
                              distribution=(self.claim_global_time(),),
                              payload=(circ_id,))
        self.dispersy.endpoint.send([candidate], [message.packet])
        
    def send_created(self, destination, circ_id):
        candidate = self.dispersy.get_candidate(destination)
            
        meta = self.get_meta_message(u"created")
        message = meta.impl(authentication=(self.my_member,),
                              distribution=(self.claim_global_time(),),
                              payload=(circ_id,))
        self.dispersy.endpoint.send([candidate], [message.packet])
        
    def send_data(self, destination, circ_id, ultimate_destination, data = None, origin = None):
        candidate = self.dispersy.get_candidate(destination)      
            
        meta = self.get_meta_message(u"data")
        message = meta.impl(authentication=(self.my_member,),
                              distribution=(self.claim_global_time(),),
                              payload=(circ_id, ultimate_destination, data,origin))
        
        self.dispersy.endpoint.send([candidate], [message.packet])
        
    def send_extend(self, destination, circ_id, extend_with):
        candidate = self.dispersy.get_candidate(destination) 
        
        if not isinstance(candidate, Candidate):
            return     
            
        meta = self.get_meta_message(u"extend")
        message = meta.impl(authentication=(self.my_member,),
                              distribution=(self.claim_global_time(),),
                              payload=(circ_id, extend_with,))
        
        self.dispersy.endpoint.send([candidate], [message.packet])
        
    def send_extended(self, destination, circ_id, extended_with):
        candidate = self.dispersy.get_candidate(destination)      
            
        meta = self.get_meta_message(u"extended")
        message = meta.impl(authentication=(self.my_member,),
                              distribution=(self.claim_global_time(),),
                              payload=(circ_id, extended_with,))
        
        self.dispersy.endpoint.send([candidate], [message.packet])

    def on_introduction_request(self, messages):
        try:
            return self._original_on_introduction_request(messages)
        finally:
            for message in messages:
                if not isinstance(message.candidate, BootstrapCandidate):
                    self.fire("on_member_heartbeat", candidate = message.candidate)

    def on_introduction_response(self, messages):
        try:
            return self._original_on_introduction_response(messages)
        finally:
            for message in messages:
                if not isinstance(message.candidate, BootstrapCandidate):
                    self.fire("on_member_heartbeat", candidate = message.candidate)