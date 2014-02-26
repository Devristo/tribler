from collections import defaultdict
import logging
import sqlite3
import uuid
import time

from Tribler.community.anontunnel.events import TunnelObserver

__author__ = 'chris'


class CircuitStats:
    def __init__(self):
        self.timestamp = None
        self.times = []
        self.bytes_up_list = []
        self.bytes_down_list = []

        self.bytes_down = [0, 0]
        self.bytes_up = [0, 0]

        self.speed_up = 0.0
        self.speed_down = 0.0

    @property
    def bytes_downloaded(self):
        return self.bytes_down[1]

    @property
    def bytes_uploaded(self):
        return self.bytes_up[1]


class RelayStats:
    def __init__(self):
        self.timestamp = None

        self.times = []
        self.bytes_list = []
        self.bytes = [0, 0]
        self.speed = 0


class StatsCollector(TunnelObserver):
    def __init__(self, proxy):
        """
        @type proxy: Tribler.community.anontunnel.community.ProxyCommunity
        """

        TunnelObserver.__init__(self)
        
        self._logger = logging.getLogger(__name__)
        
        self.stats = {
            'bytes_returned': 0,
            'bytes_exit': 0,
            'bytes_enter': 0,
            'broken_circuits': 0
        }
        self.download_stats = {}
        self.session_id = uuid.uuid4()
        self.proxy = proxy
        self.running = False
        self.circuit_stats = defaultdict(lambda: CircuitStats())
        ''':type : dict[int, CircuitStats] '''
        self.relay_stats = defaultdict(lambda: RelayStats())
        ''':type : dict[((str,int),int), RelayStats] '''
        self._circuit_cache = {}
        ''':type : dict[int, Circuit] '''

    def pause(self):
        """
        Pause stats collecting
        """
        self.running = False
        self.proxy.observers.remove(self)

    def clear(self):
        """
        Clear collected stats
        """

        self.circuit_stats.clear()
        self.relay_stats.clear()

    def stop(self):
        self.pause()
        self.clear()

    def start(self):
        if self.running:
            raise ValueError("Cannot start an already running stats collector")

        self._logger.error("Resuming stats collecting!")
        self.running = True
        self.proxy.observers.append(self)
        self.proxy.dispersy.callback.register(self.__calc_speeds)

    def on_break_circuit(self, circuit):
        if len(circuit.hops) == circuit.goal_hops:
            self.stats['broken_circuits'] += 1

    def __calc_speeds(self):
        while self.running:
            t2 = time.time()
            self._circuit_cache.update(self.proxy.circuits)

            for circuit_id in self.proxy.circuits.keys():
                c = self.circuit_stats[circuit_id]

                if c.timestamp is None:
                    c.timestamp = time.time()
                elif c.timestamp < t2:

                    if len(c.bytes_up_list) == 0 or c.bytes_up[-1] != \
                            c.bytes_up_list[-1] and c.bytes_down[-1] != \
                            c.bytes_down_list[-1]:
                        c.bytes_up_list.append(c.bytes_up[-1])
                        c.bytes_down_list.append(c.bytes_down[-1])
                        c.times.append(t2)

                    c.speed_up = 1.0 * (c.bytes_up[1] - c.bytes_up[0]) / (
                        t2 - c.timestamp)
                    c.speed_down = 1.0 * (
                        c.bytes_down[1] - c.bytes_down[0]) / (t2 - c.timestamp)

                    c.timestamp = t2
                    c.bytes_up = [c.bytes_up[1], c.bytes_up[1]]
                    c.bytes_down = [c.bytes_down[1], c.bytes_down[1]]

            for relay_key in self.proxy.relay_from_to.keys():
                r = self.relay_stats[relay_key]

                if r.timestamp is None:
                    r.timestamp = time.time()
                elif r.timestamp < t2:
                    changed = len(r.bytes_list) == 0 \
                        or r.bytes[-1] != r.bytes_list[-1]

                    if changed:
                        r.bytes_list.append(r.bytes[-1])
                        r.times.append(t2)

                    r.speed = 1.0 * (r.bytes[1] - r.bytes[0]) / (
                        t2 - r.timestamp)
                    r.timestamp = t2
                    r.bytes = [r.bytes[1], r.bytes[1]]

            yield 1.0

    def on_enter_tunnel(self, circuit_id, candidate, origin, payload):
        self.stats['bytes_enter'] += len(payload)

    def on_incoming_from_tunnel(self, community, circuit, origin, data):
        self.stats['bytes_returned'] += len(data)
        self.circuit_stats[circuit.circuit_id].bytes_down[1] += len(data)

    def on_exiting_from_tunnel(self, circuit_id, candidate, destination, data):
        self.stats['bytes_exit'] += len(data)

        valid = False if circuit_id not in self.proxy.circuits \
            else self.proxy.circuits[circuit_id].goal_hops == 0

        if valid:
            self.circuit_stats[circuit_id].bytes_up[-1] += len(data)

    def on_send_data(self, circuit_id, candidate, destination,
                     payload):
        self.circuit_stats[circuit_id].bytes_up[-1] += len(payload)

    def on_relay(self, from_key, to_key, direction, data):
        self.relay_stats[from_key].bytes[-1] += len(data)
        self.relay_stats[to_key].bytes[-1] += len(data)

    def _create_stats(self):
        stats = {
            'uuid': str(self.session_id),
            'swift': self.download_stats,
            'bytes_enter': self.stats['bytes_enter'],
            'bytes_exit': self.stats['bytes_exit'],
            'bytes_return': self.stats['bytes_returned'],
            'broken_circuits': self.stats['broken_circuits'],
            'circuits': [
                {
                    'hops': self._circuit_cache[circuit_id].goal_hops,
                    'bytes_down': c.bytes_down_list[-1] - c.bytes_down_list[0],
                    'bytes_up': c.bytes_up_list[-1] - c.bytes_up_list[0],
                    'time': c.times[-1] - c.times[0]
                }
                for circuit_id, c in self.circuit_stats.items()
                if len(c.times) >= 2
            ],
            'relays': [
                {
                    'bytes': r.bytes_list[-1],
                    'time': r.times[-1] - r.times[0]
                }
                for r in self.relay_stats.values()
                if r.times and len(r.times) >= 2
            ]
        }

        return stats

    def on_unload(self):
        if self.download_stats:
            self._logger.error("Sharing statistics now!")
            self.share_stats()

    def share_stats(self):
        self.proxy.send_stats(self._create_stats())


class StatsCrawler(TunnelObserver):
    """
    Stores incoming stats in a SQLite database
    @param RawServer raw_server: the RawServer instance to queue database tasks
    on
    """

    def __init__(self, raw_server):
        TunnelObserver.__init__(self)
        self._logger = logging.getLogger(__name__)
        self._logger.warning("Running StatsCrawler")
        self.raw_server = raw_server
        self.conn = None

        def init_sql():
            self.conn = sqlite3.connect("results.db")

            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS result(
                    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id GUID UNIQUE,
                    time DATETIME,
                    host,
                    port,
                    swift_size,
                    swift_time,
                    bytes_enter,
                    bytes_exit,
                    bytes_returned
                )
             ''')

            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS result_circuit (
                    result_circuit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id,
                    hops,
                    bytes_up,
                    bytes_down,
                    time
                )
            ''')

            self.conn.execute('''
            CREATE TABLE IF NOT EXISTS result_relay(
                result_relay_id INTEGER PRIMARY KEY AUTOINCREMENT,
                result_id,
                bytes,
                time
            )
            ''')

        self.raw_server.add_task(init_sql)

    def on_tunnel_stats(self, community, candidate, stats):
        self.raw_server.add_task(
            lambda: self.on_stats(community, candidate, stats))

    def on_stats(self, community, candidate, stats):
        sock_address = candidate.sock_addr
        cursor = self.conn.cursor()

        try:
            cursor.execute(
                '''INSERT OR FAIL INTO result
                    (
                        encryption, session_id, time,
                        host, port, swift_size, swift_time,
                        bytes_enter, bytes_exit, bytes_returned
                    )
                    VALUES (1, ?,DATETIME('now'),?,?,?,?,?,?,?)''',
                [uuid.UUID(stats['uuid']), sock_address[0], sock_address[1],
                 stats['swift']['size'], stats['swift']['download_time'],
                 stats['bytes_enter'], stats['bytes_exit'],
                 stats['bytes_return']]
            )

            result_id = cursor.lastrowid

            for circuit in stats['circuits']:
                cursor.execute('''
                    INSERT INTO result_circuit (
                        result_id, hops, bytes_up, bytes_down, time
                    ) VALUES (?, ?, ?, ?, ?)''',
                               [
                                   result_id, circuit['hops'],
                                   circuit['bytes_up'],
                                   circuit['bytes_down'],
                                   circuit['time']
                               ])

            for relay in stats['relays']:
                cursor.execute('''
                    INSERT INTO result_relay (result_id, bytes, time)
                        VALUES (?, ?, ?)
                ''', [result_id, relay['bytes'], relay['time']])

            self.conn.commit()

            self._logger.warning("Storing stats data of %s:%d" % sock_address)
        except sqlite3.IntegrityError:
            self._logger.error("Stat already exists of %s:%d" % sock_address)
        except BaseException:
            self._logger.exception()

        cursor.close()

    def stop(self):
        self._logger.error("Stopping crawler")
        self.conn.close()