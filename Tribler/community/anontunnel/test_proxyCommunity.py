import logging.config
import os
from unittest import TestCase
import time
from mock import Mock
from Tribler.Core.Session import Session
from Tribler.Core.SessionConfig import SessionStartupConfig
from Tribler.community.anontunnel import exitstrategies
from Tribler.community.anontunnel.Socks5.server import Socks5Server
from Tribler.community.anontunnel.cache import CandidateCache
from Tribler.community.anontunnel.community import ProxyCommunity
from Tribler.community.anontunnel.events import TunnelObserver
from Tribler.community.anontunnel.globals import MESSAGE_CREATED, MESSAGE_CREATE, \
    CIRCUIT_STATE_READY, CIRCUIT_STATE_EXTENDING, CIRCUIT_STATE_BROKEN, MESSAGE_EXTEND, \
    MESSAGE_PONG
from Tribler.community.anontunnel.payload import CreateMessage, CreatedMessage, ExtendedMessage, ExtendMessage, \
    DataMessage, PingMessage, PongMessage
from Tribler.community.anontunnel.routing import Circuit
from Tribler.dispersy.candidate import WalkCandidate
from Tribler.dispersy.endpoint import NullEndpoint
from Tribler.dispersy.member import Member

__author__ = 'Chris'

logging.config.fileConfig(
    os.path.dirname(os.path.realpath(__file__)) + "/logger.conf")


class TestProxyCommunity(TestCase):

    @classmethod
    def setUpClass(cls):
        config = SessionStartupConfig()
        config.set_torrent_checking(False)
        config.set_multicast_local_peer_discovery(False)
        config.set_megacache(False)
        config.set_dispersy(True)
        config.set_swift_proc(False)
        config.set_mainline_dht(False)
        config.set_torrent_collecting(False)
        config.set_libtorrent(False)
        config.set_dht_torrent_collecting(False)
        cls.session_config = config
        cls.session = Session(scfg=cls.session_config)
        cls.session.start()
        while not cls.session.lm.initComplete:
            time.sleep(1)
        cls.dispersy = cls.session.lm.dispersy
        cls.dispersy._endpoint = NullEndpoint()
        ''' :type : Tribler.dispersy.Dispersy '''

        cls.__candidate_counter = 0

    def setUp(self):
        dispersy = self.dispersy
        keypair = dispersy.crypto.generate_key(u"NID_secp160k1")
        dispersy_member = dispersy.callback.call(dispersy.get_member, (dispersy.crypto.key_to_bin(keypair.pub()), dispersy.crypto.key_to_bin(keypair)))

        self.community = None
        ''' :type : ProxyCommunity '''

        def load_community():
            proxy_community = dispersy.define_auto_load(ProxyCommunity, (dispersy_member, None, None), load=True)[0]
            ''' :type : ProxyCommunity '''
            exitstrategies.DefaultExitStrategy(self.session.lm.rawserver, proxy_community)

            self.community = proxy_community

        self.dispersy.callback.call(load_community)

    def __create_walk_candidate(self):
        candidate = WalkCandidate(("127.0.0.1", self.__candidate_counter), False, ("127.0.0.1", self.__candidate_counter), ("127.0.0.1", self.__candidate_counter), u'unknown')
        key = self.dispersy.crypto.generate_key(u"NID_secp160k1")
        ''' :type : EC '''

        member = []
        def create_member():
            member.append(Member(self.dispersy, self.dispersy.crypto.key_to_bin(key.pub())))

        self.dispersy.callback.call(create_member)

        candidate.associate(member[0])
        self.__candidate_counter += 1
        candidate.walk(time.time(), 0.0)
        return candidate

    def tearDown(self):
        del self.dispersy._auto_load_communities[self.community.get_classification()]
        self.community.unload_community()

    def test_on_create(self):
        create_sender = self.__create_walk_candidate()

        create_message = CreateMessage()
        circuit_id = 1337

        self.community.send_message = send_message = Mock()
        self.community.on_create(circuit_id, create_sender, create_message)

        args, keyargs = send_message.call_args

        self.assertEqual(create_sender, keyargs['destination'])
        self.assertEqual(circuit_id, keyargs['circuit_id'])
        self.assertEqual(MESSAGE_CREATED, keyargs['message_type'])
        self.assertIsInstance(keyargs['message'], CreatedMessage)

    def test_create_circuit(self):
        create_sender = self.__create_walk_candidate()

        self.assertRaises(ValueError, self.community.create_circuit, create_sender, 0)

        self.community.send_message = send_message = Mock()

        hops = 1
        circuit = self.community.create_circuit(create_sender, hops)

        # Newly created circuit should be stored in circuits dict
        self.assertIsInstance(circuit, Circuit)
        self.assertEqual(create_sender, circuit.candidate)
        self.assertEqual(hops, circuit.goal_hops)
        self.assertIn(circuit.circuit_id, self.community.circuits)
        self.assertEqual(circuit, self.community.circuits[circuit.circuit_id])
        self.assertEqual(CIRCUIT_STATE_EXTENDING, circuit.state)

        # We must have sent a CREATE message to the candidate in question
        args, kwargs = send_message.call_args
        destination, reply_circuit, message_type, created_message = args
        self.assertEqual(circuit.circuit_id, reply_circuit)
        self.assertEqual(create_sender, destination)
        self.assertEqual(MESSAGE_CREATE, message_type)
        self.assertIsInstance(created_message, CreateMessage)

    def test_on_created(self):
        first_hop = self.__create_walk_candidate()
        circuit = self.community.create_circuit(first_hop, 1)

        self.community.on_created(circuit.circuit_id, first_hop, CreatedMessage([]))
        self.assertEqual(CIRCUIT_STATE_READY, circuit.state)

    def on_extended(self):
        cache = CandidateCache(self.community)

        # 2 Hop - should fail due to no extend candidates
        first_hop = self.__create_walk_candidate()
        circuit = self.community.create_circuit(first_hop, 2)

        result = self.community.on_created(circuit.circuit_id, first_hop, CreatedMessage([]))
        self.assertFalse(result)
        self.assertEqual(CIRCUIT_STATE_BROKEN, circuit.state)

        # 2 Hop - should succeed
        second_hop = self.__create_walk_candidate()
        cache.cache(second_hop) # just easy way to get the keys

        candidate_dict = {}
        candidate_dict[cache.candidate_to_hashed_key[second_hop]] = cache.candidate_to_key_string[second_hop]
        circuit = self.community.create_circuit(first_hop, 2)

        self.community.send_message = send_message = Mock()

        result = self.community.on_created(circuit.circuit_id, first_hop, CreatedMessage(candidate_dict))
        self.assertTrue(result)

        # ProxyCommunity should send an EXTEND message with the hash of second_hop's pub-key
        args, kwargs = send_message.call_args
        circuit_candidate, circuit_id, message_type, message = args

        self.assertEqual(first_hop, circuit_candidate)
        self.assertEqual(circuit.circuit_id, circuit_id)
        self.assertEqual(MESSAGE_EXTEND, message_type)
        self.assertIsInstance(message, ExtendMessage)
        self.assertEqual(message.extend_with, cache.candidate_to_hashed_key[second_hop])

        # Upon reception of the ON_EXTENDED the circuit should reach it full 2-hop length and thus be ready for use
        result = self.community.on_extended(circuit.circuit_id, first_hop, ExtendedMessage(None, []))
        self.assertTrue(result)
        self.assertEqual(CIRCUIT_STATE_READY, circuit.state)

    def test_remove_circuit(self):
        first_hop = self.__create_walk_candidate()
        circuit = self.community.create_circuit(first_hop, 1)

        self.assertIn(circuit.circuit_id, self.community.circuits)
        self.community.remove_circuit(circuit.circuit_id)
        self.assertNotIn(circuit, self.community.circuits)

    def test_on_data(self):
        first_hop = self.__create_walk_candidate()
        circuit = self.community.create_circuit(first_hop, 1)
        self.community.on_created(circuit.circuit_id, first_hop, CreatedMessage([]))

        payload = "Hello world"
        origin = ("google.com", 80)
        data_message = DataMessage(None, payload, origin=origin)

        observer = TunnelObserver()
        observer.on_incoming_from_tunnel = on_incoming_from_tunnel = Mock()
        self.community.observers.append(observer)

        # Its on our own circuit so it should trigger the on_incoming_from_tunnel event
        self.community.on_data(circuit.circuit_id, first_hop, data_message)
        on_incoming_from_tunnel.assert_called_with(self.community, circuit, origin, payload)

        # Not our own circuit so we need to exit it
        destination = ("google.com", 80)
        exit_message = DataMessage(destination, payload, origin=None)
        observer.on_exiting_from_tunnel = on_exiting_from_tunnel = Mock()
        self.community.on_data(1337, first_hop, exit_message)
        on_exiting_from_tunnel.assert_called_with(1337, first_hop, destination, payload)

    def test_on_extend(self):
        cache = CandidateCache(self.community)

        # We mimick the intermediary hop ( ORIGINATOR - INTERMEDIARY - NODE_TO_EXTEND_ORIGINATORS_CIRCUIT_WITH )
        originator = self.__create_walk_candidate()
        node_to_extend_with = self.__create_walk_candidate()
        originator_circuit_id = 1337

        cache.cache(originator)
        cache.cache(node_to_extend_with)
        hashed_key = cache.candidate_to_hashed_key[node_to_extend_with]

        # make sure our node_to_extend_with comes up when yielding verified candidates
        self.community.add_candidate(node_to_extend_with)

        self.community.send_message = send_message = Mock()
        self.community.on_create(originator_circuit_id, originator, CreateMessage())

        # Check whether we are sending node_to_extend_with in the CreatedMessage reply
        args, kwargs = send_message.call_args
        created_message = kwargs['message']
        candidate_dict = created_message.candidate_list
        self.assertIsInstance(created_message, CreatedMessage)
        self.assertIn(hashed_key, candidate_dict)
        self.assertIn(node_to_extend_with, self.community.candidate_cache.candidates)

        self.community.on_extend(originator_circuit_id, originator, ExtendMessage(hashed_key))

        # Check whether we are sending a CREATE to node_to_extend_with
        args, kwargs = send_message.call_args
        create_destination, circuit_id, message_type, message = args
        self.assertEqual(node_to_extend_with, create_destination)
        self.assertEqual(MESSAGE_CREATE, message_type)
        self.assertIsInstance(message, CreateMessage)

        # Check whether the routing table has been updated
        relay_from_originator = (originator.sock_addr, originator_circuit_id)
        relay_from_endpoint = (node_to_extend_with.sock_addr, circuit_id)

        self.assertIn(relay_from_originator, self.community.relay_from_to)
        self.assertIn(relay_from_endpoint, self.community.relay_from_to)

    def test_on_pong(self):
        first_hop = self.__create_walk_candidate()
        circuit = self.community.create_circuit(first_hop, 1)
        self.community.on_created(circuit.circuit_id, first_hop, CreatedMessage({}))

        result = self.community.on_pong(circuit.circuit_id, first_hop, PongMessage())
        self.assertFalse(result, "Cannot handle a pong when we never sent a PING")

        self.community.create_ping(first_hop, circuit.circuit_id)

        # Check whether the circuit last incoming time is correct after the pong
        circuit.last_incoming = 0
        result = self.community.on_pong(circuit.circuit_id, first_hop, PongMessage())
        self.assertTrue(result)

        self.assertAlmostEqual(circuit.last_incoming, time.time(), delta=0.5)

    def test_on_ping(self):
        circuit_id = 1337
        first_hop = self.__create_walk_candidate()
        self.community.add_candidate(first_hop)

        self.community.on_create(circuit_id, first_hop, CreateMessage())

        self.community.send_message = send_message = Mock()
        self.community.on_ping(circuit_id, first_hop, PingMessage())

        # Check whether we responded with a pong
        args, kwargs = send_message.call_args

        self.assertEqual(first_hop, kwargs['destination'])
        self.assertEqual(circuit_id, kwargs['circuit_id'])
        self.assertEqual(MESSAGE_PONG, kwargs['message_type'])
        self.assertIsInstance(kwargs['message'], PongMessage)