# Written by Jie Yang
# Modified by George Milescu
# see LICENSE.txt for license information
# Note for Developers: Please write a unittest in Tribler/Test/test_sqlitecachedbhandler.py
# for any function you add to database.
# Please reuse the functions in sqlitecachedb as much as possible
import binascii
import logging
import os
import threading
import urllib
from binascii import hexlify
from copy import deepcopy
from random import sample
from struct import unpack_from
from threading import RLock, Lock
from time import time
from traceback import print_exc

from twisted.internet.base import DelayedCall
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall

from Notifier import Notifier
from Tribler.Category.Category import Category
from Tribler.Core.CacheDB.sqlitecachedb import SQLiteCacheDB, bin2str, str2bin
from Tribler.Core.RemoteTorrentHandler import RemoteTorrentHandler
from Tribler.Core.Search.SearchManager import split_into_keywords, filter_keywords
from Tribler.Core.TorrentDef import TorrentDef
from Tribler.Core.Utilities.unicode import dunno2unicode
from Tribler.Core.simpledefs import (INFOHASH_LENGTH, NTFY_PEERS, NTFY_UPDATE, NTFY_INSERT, NTFY_DELETE, NTFY_CREATE,
                                     NTFY_MODIFIED, NTFY_TRACKERINFO, NTFY_MYPREFERENCES, NTFY_VOTECAST, NTFY_TORRENTS,
                                     NTFY_CHANNELCAST, NTFY_COMMENTS, NTFY_PLAYLISTS, NTFY_MODIFICATIONS,
                                     NTFY_MODERATIONS, NTFY_MARKINGS, NTFY_STATE)
from Tribler.dispersy.taskmanager import TaskManager


try:
    # python 2.7 only...
    from collections import OrderedDict
except ImportError:
    from Tribler.dispersy.python27_ordereddict import OrderedDict

try:
    WindowsError
except NameError:
    WindowsError = Exception

SHOW_ERROR = False

VOTECAST_FLUSH_DB_INTERVAL = 15

MAX_KEYWORDS_STORED = 5
MAX_KEYWORD_LENGTH = 50

# Rahim:
MAX_POPULARITY_REC_PER_TORRENT = 5  # maximum number of records in popularity table for each torrent
MAX_POPULARITY_REC_PER_TORRENT_PEER = 3  # maximum number of records per each combination of torrent and peer


DEFAULT_ID_CACHE_SIZE = 1024 * 5

class LimitedOrderedDict(OrderedDict):

    def __init__(self, limit, *args, **kargs):
        super(LimitedOrderedDict, self).__init__(*args, **kargs)
        self._limit = limit

    def __setitem__(self, *args, **kargs):
        super(LimitedOrderedDict, self).__setitem__(*args, **kargs)
        if len(self) > self._limit:
            self.popitem(last=False)


class BasicDBHandler(TaskManager):
    _singleton_lock = RLock()
    _single = None

    def __init__(self, db, table_name):  # # self, table_name
        super(BasicDBHandler, self).__init__()

        self._logger = logging.getLogger(self.__class__.__name__)

        self._db = db  # # SQLiteCacheDB.getInstance()
        self.table_name = table_name
        self.notifier = Notifier.getInstance()

    @classmethod
    def getInstance(cls, *args, **kargs):
        with cls._singleton_lock:
            if not cls._single:
                cls._single = cls(*args, **kargs)
            return cls._single

    @classmethod
    def delInstance(cls):
        if cls._single:
            # cancel all pending tasks
            cls._single.cancel_all_pending_tasks()

        with cls._singleton_lock:
            cls._single = None

    @classmethod
    def hasInstance(cls):
        return cls._single != None

    def close(self):
        self.cancel_all_pending_tasks()

        try:
            self._db.close()
        except:
            if SHOW_ERROR:
                print_exc()

    def size(self):
        return self._db.size(self.table_name)

    def getOne(self, value_name, where=None, conj='and', **kw):
        return self._db.getOne(self.table_name, value_name, where=where, conj=conj, **kw)

    def getAll(self, value_name, where=None, group_by=None, having=None, order_by=None, limit=None, offset=None, conj='and', **kw):
        return self._db.getAll(self.table_name, value_name, where=where, group_by=group_by, having=having, order_by=order_by, limit=limit, offset=offset, conj=conj, **kw)


class MiscDBHandler(BasicDBHandler):

    def __init__(self):
        if MiscDBHandler._single:
            raise RuntimeError("MiscDBHandler is singleton")
        db = SQLiteCacheDB.getInstance()
        BasicDBHandler.__init__(self, db, None)

        self.initialize()

    def initialize(self):
        # initialize TorrentStatus name-ID tables
        self._torrent_status_name2id_dict = {u'unknown': 0, u'good': 1, u'dead': 2}
        sql = u'SELECT LOWER(name), status_id FROM TorrentStatus'
        st = self._db.fetchall(sql)
        self._torrent_status_name2id_dict.update(dict(st))

        self._torrent_status_id2name_dict = \
            dict([(x, y) for (y, x) in self._torrent_status_name2id_dict.iteritems()])
        self._torrent_status_id2name_dict[None] = 'unknown'

        # initialize Category name-ID tables
        self._category_name2id_dict = { u'Video': 1, u'VideoClips': 2,
            u'Audio': 3, u'Compressed': 4, u'Document': 5,
            u'Picture': 6, u'xxx': 7, u'other': 8, }
        sql = u'SELECT LOWER(name), category_id FROM Category'
        ct = self._db.fetchall(sql)
        self._category_name2id_dict.update(dict(ct))
        self._category_name2id_dict[u'unknown'] = 0

        self._category_id2name_dict = \
            dict([(x, y) for (y, x) in self._category_name2id_dict.iteritems()])
        self._category_id2name_dict[None] = u'unknown'

        # initialize TorrentSource name-ID tables
        sql = u'SELECT name, source_id FROM TorrentSource'
        st = self._db.fetchall(sql)
        self._torrent_source_name2id_dict = dict(st)
        self._torrent_source_id2name_dict = \
            dict([(x, y) for (y, x) in self._torrent_source_name2id_dict.iteritems()])
        self._torrent_source_id2name_dict[None] = u'unknown'

    def torrentStatusName2Id(self, status_name):
        return self._torrent_status_name2id_dict.get(status_name.lower(), 0)

    def torrentStatusId2Name(self, status_id):
        return self._torrent_status_id2name_dict.get(status_id, None)

    def categoryName2Id(self, category_name):
        category_id = 0
        if category_name is not None and len(category_name) > 0:
            category = category_name[0].lower()
            category_id = self._category_name2id_dict[category]
        return category_id

    def categoryId2Name(self, category_id):
        return self._category_id2name_dict[category_id]

    def torrentSourceName2Id(self, source_name):
        if source_name in self._torrent_source_name2id_dict:
            source_id = self._torrent_source_name2id_dict[source_name]
        else:
            source_id = self._addSource(source_name)
            self._torrent_source_name2id_dict[source_name] = source_id
            self._torrent_source_id2name_dict[source_id] = source_name
        return source_id

    def torrentSourceId2Name(self, source_id):
        return self._torrent_source_id2name_dict.get(source_id, None)

    def _addSource(self, source):
        desc = u''
        if source.startswith('http') and source.endswith('xml'):
            desc = u'RSS'
        self._db.insert(u'TorrentSource', name=source, description=desc)
        source_id = self._db.getOne(u'TorrentSource', u'source_id', name=source)
        return source_id


class MetadataDBHandler(BasicDBHandler):

    def __init__(self):
        if MetadataDBHandler._single:
            raise RuntimeError("MetadataDBHandler is singleton")
        db = SQLiteCacheDB.getInstance()
        BasicDBHandler.__init__(self, db, None)
        self.category = Category.getInstance()
        self.misc_db = MiscDBHandler.getInstance()
        self.torrent_db = TorrentDBHandler.getInstance()

    def getMetadataMessageList(self, infohash, roothash, columns):
        """
        Gets a list of metadata messages with the given hash-type and
        hash-value.
        """
        infohash_str = bin2str(infohash) if infohash else None
        roothash_str = bin2str(roothash) if roothash else None

        column_str = ",".join(columns)
        sql = "SELECT %s FROM MetadataMessage WHERE infohash = ? OR roothash = ?" % column_str
        raw_result_list = self._db.fetchall(sql, (infohash_str, roothash_str))

        processed_result_list = []
        if raw_result_list:
            for raw_result in raw_result_list:
                this_result = []

                for idx, column in enumerate(columns):
                    if raw_result[idx] == None:
                        this_result.append(None)

                    elif column == "infohash":
                        this_result.append(str2bin(raw_result[idx]))
                    elif column == "roothash":
                        this_result.append(str2bin(raw_result[idx]))
                    elif column == "this_mid":
                        this_result.append(str(raw_result[idx]))
                    elif column == "previous_mid":
                        this_result.append(str(raw_result[idx]))
                    else:
                        this_result.append(raw_result[idx])

                processed_result_list.append(tuple(this_result))

        return processed_result_list

    def addAndGetIDMetadataMessage(self, dispersy_id, this_global_time, this_mid,
            infohash, roothash, prev_mid=None, prev_global_time=None):
        """
        Adds a Metadata message and get its message ID.
        """
        this_mid_str = buffer(this_mid) if this_mid else None
        prev_mid_str = buffer(prev_mid) if prev_mid else None

        infohash_str = bin2str(infohash) if infohash else None
        roothash_str = bin2str(roothash) if roothash else None

        sql = """INSERT INTO MetadataMessage(dispersy_id, this_global_time,
                this_mid, infohash, roothash, previous_mid, previous_global_time)
            VALUES(?, ?, ?, ?, ?, ?, ?);
            SELECT last_insert_rowid();
        """
        values = (dispersy_id, this_global_time, this_mid_str,
            infohash_str, roothash_str,
            prev_mid_str, prev_global_time)

        result = self._db.fetchone(sql, values)
        self.notifier.notify(NTFY_TORRENTS, NTFY_UPDATE, infohash)
        return result

    def addMetadataDataInBatch(self, value_tuple_list):
        """
        Adds metadata data in batch.
        """
        sql = "INSERT INTO MetadataData(message_id, data_key, data_value) VALUES(?, ?, ?)"
        self._db.executemany(sql, value_tuple_list)

    def deleteMetadataMessage(self, dispersy_id):
        sql = "DELETE FROM MetadataMessage WHERE dispersy_id = ?"
        self._db.execute_write(sql, (dispersy_id,))

    def getMetdataDateByInfohash(self, infohash):
        sql = """
        SELECT data.data_key, data.data_value
        FROM MetadataMessage as msg, MetadataData as data
        WHERE msg.infohash = ? AND msg.message_id = data.message_id
        """
        result = self._db.fetchall(sql, (bin2str(infohash),))
        return result

    def getMetadataData(self, message_id):
        sql = "SELECT data_key, data_value FROM MetadataData WHERE message_id = ?"
        result = self._db.fetchall(sql, (message_id,))
        return result

    def getThumbnailTorrents(self, keys, limit=20):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, MetadataData, MetadataMessage WHERE MetadataData.message_id = MetadataMessage.message_id AND MetadataMessage.infohash = Torrent.infohash AND data_key='swift-thumbs' AND Torrent.name <> '' AND Torrent.name IS NOT NULL " + self.category.get_family_filter_sql(self.misc_db.categoryName2Id) + " ORDER BY this_global_time DESC LIMIT ?"
        results = self._db.fetchall(sql, (limit,)) or []
        for key_index, key in enumerate(keys):
            if key.endswith('hash'):
                for i in range(len(results)):
                    result = list(results[i])
                    if result[key_index]:
                        result[key_index] = str2bin(result[key_index])
                        results[i] = result
        return results

class PeerDBHandler(BasicDBHandler):

    def __init__(self):
        if PeerDBHandler._single:
            raise RuntimeError("PeerDBHandler is singleton")
        db = SQLiteCacheDB.getInstance()
        BasicDBHandler.__init__(self, db, 'Peer')

        self.permid_id = LimitedOrderedDict(DEFAULT_ID_CACHE_SIZE)

    def __len__(self):
        return self.size()

    def getPeerID(self, permid):
        return self.getPeerIDS([permid, ])[0]

    def getPeerIDS(self, permids):
        to_select = []

        for permid in permids:
            assert isinstance(permid, str), permid

            if permid not in self.permid_id:
                to_select.append(bin2str(permid))

        if len(to_select) > 0:
            parameters = ", ".join('?' * len(to_select))
            sql_get_peer_ids = "SELECT peer_id, permid FROM Peer WHERE permid IN (" + parameters + ")"
            peerids = self._db.fetchall(sql_get_peer_ids, to_select)
            for peer_id, permid in peerids:
                self.permid_id[str2bin(permid)] = peer_id

        to_return = []
        for permid in permids:
            if permid in self.permid_id:
                to_return.append(self.permid_id[permid])
            else:
                to_return.append(None)
        return to_return

    def addOrGetPeerID(self, permid):
        peer_id = self.getPeerID(permid)
        if peer_id is None:
            self.addPeer(permid, {})
            peer_id = self.getPeerID(permid)

        return peer_id

    def getPeer(self, permid, keys=None):
        if keys is not None:
            res = self.getOne(keys, permid=bin2str(permid))
            return res
        else:
            # return a dictionary
            # make it compatible for calls to old bsddb interface
            value_name = (u'peer_id', u'permid', u'name')

            item = self.getOne(value_name, permid=bin2str(permid))
            if not item:
                return None
            peer = dict(zip(value_name, item))
            peer['permid'] = str2bin(peer['permid'])
            return peer

    def getPeerById(self, peer_id, keys=None):
        if keys is not None:
            res = self.getOne(keys, peer_id=peer_id)
            return res
        else:
            # return a dictionary
            # make it compatible for calls to old bsddb interface
            value_name = (u'peer_id', u'permid', u'name')

            item = self.getOne(value_name, peer_id=peer_id)
            if not item:
                return None
            peer = dict(zip(value_name, item))
            peer['permid'] = str2bin(peer['permid'])
            return peer

    def addPeer(self, permid, value):
        # add or update a peer
        # ARNO: AAARGGH a method that silently changes the passed value param!!!
        # Jie: deepcopy(value)?

        _permid = _last_seen = _ip = _port = None
        if 'permid' in value:
            _permid = value.pop('permid')

        peer_id = self.getPeerID(permid)
        peer_existed = False
        if 'name' in value:
            value['name'] = dunno2unicode(value['name'])
        if peer_id != None:
            peer_existed = True
            where = u'peer_id=%d' % peer_id
            self._db.update('Peer', where, **value)
        else:
            self._db.insert_or_ignore('Peer', permid=bin2str(permid), **value)

        if _permid is not None:
            value['permid'] = permid

        if peer_existed:
            self.notifier.notify(NTFY_PEERS, NTFY_UPDATE, permid)
        else:
            self.notifier.notify(NTFY_PEERS, NTFY_INSERT, permid)

    def hasPeer(self, permid, check_db=False):
        if not check_db:
            return bool(self.getPeerID(permid))
        else:
            permid_str = bin2str(permid)
            sql_get_peer_id = "SELECT peer_id FROM Peer WHERE permid==?"
            peer_id = self._db.fetchone(sql_get_peer_id, (permid_str,))
            if peer_id is None:
                return False
            else:
                return True

    def updatePeer(self, permid, **argv):
        self._db.update(self.table_name, 'permid=' + repr(bin2str(permid)), **argv)
        self.notifier.notify(NTFY_PEERS, NTFY_UPDATE, permid)

    def deletePeer(self, permid=None, peer_id=None):
        # don't delete friend of superpeers, except that force is True
        if peer_id is None:
            peer_id = self.getPeerID(permid)
        if peer_id is None:
            return

        deleted = False
        if peer_id != None:
            self._db.delete('Peer', peer_id=peer_id)
            deleted = not self.hasPeer(permid, check_db=True)
            if deleted and permid in self.permid_id:
                self.permid_id.pop(permid)

        self.notifier.notify(NTFY_PEERS, NTFY_DELETE, permid)


class TorrentDBHandler(BasicDBHandler):

    def __init__(self):
        if TorrentDBHandler._single is not None:
            raise RuntimeError("TorrentDBHandler is singleton")

        db = SQLiteCacheDB.getInstance()
        BasicDBHandler.__init__(self, db, 'Torrent')  # # self,db,torrent

        self.torrent_dir = None

        self.keys = ['torrent_id', 'name', 'torrent_file_name',
                'length', 'creation_date', 'num_files', 'thumbnail',
                'insert_time', 'secret', 'relevance',
                'source_id', 'category_id', 'status_id',
                'num_seeders', 'num_leechers', 'comment', 'swift_hash', 'swift_torrent_hash',
                'last_tracker_check']
        self.existed_torrents = set()

        self.value_name = ['C.torrent_id', 'category_id', 'status_id', 'name', 'creation_date', 'num_files',
                      'num_leechers', 'num_seeders', 'length',
                      'secret', 'insert_time', 'source_id', 'torrent_file_name',
                      'relevance', 'infohash', 'last_tracker_check']

        self.value_name_for_channel = ['C.torrent_id', 'infohash', 'name',
                'torrent_file_name', 'length', 'creation_date', 'num_files',
                'thumbnail', 'insert_time', 'secret', 'relevance', 'source_id',
                'category_id', 'status_id', 'num_seeders', 'num_leechers', 'comment']
        self.category = Category.getInstance()

        self.misc_db = MiscDBHandler.getInstance()
        self.mypref_db = self.votecast_db = self.channelcast_db = self._rtorrent_handler = None

        self.infohash_id = LimitedOrderedDict(DEFAULT_ID_CACHE_SIZE)

    def register(self, torrent_dir):
        self.torrent_dir = torrent_dir

        self.misc_db = MiscDBHandler.getInstance()
        self.mypref_db = MyPreferenceDBHandler.getInstance()
        self.votecast_db = VoteCastDBHandler.getInstance()
        self.channelcast_db = ChannelCastDBHandler.getInstance()
        self._rtorrent_handler = RemoteTorrentHandler.getInstance()

    def getTorrentID(self, infohash):
        return self.getTorrentIDS([infohash, ])[0]

    def getTorrentIDS(self, infohashes):
        to_select = []

        for infohash in infohashes:
            assert isinstance(infohash, str), "INFOHASH has invalid type: %s" % type(infohash)
            assert len(infohash) == INFOHASH_LENGTH, "INFOHASH has invalid length: %d" % len(infohash)

            if not infohash in self.infohash_id:
                to_select.append(bin2str(infohash))

        while len(to_select) > 0:
            nrToQuery = min(len(to_select), 50)
            parameters = '?,' * nrToQuery
            sql_get_torrent_ids = "SELECT torrent_id, infohash FROM Torrent WHERE infohash IN (" + parameters[:-1] + ")"

            torrents = self._db.fetchall(sql_get_torrent_ids, to_select[:nrToQuery])
            for torrent_id, infohash in torrents:
                self.infohash_id[str2bin(infohash)] = torrent_id

            to_select = to_select[nrToQuery:]

        to_return = []
        for infohash in infohashes:
            if infohash in self.infohash_id:
                to_return.append(self.infohash_id[infohash])
            else:
                to_return.append(None)
        return to_return

    def getTorrentIDRoot(self, roothash):
        assert isinstance(roothash, str), "roothash has invalid type: %s" % type(roothash)
        assert len(roothash) == INFOHASH_LENGTH, "roothash has invalid length: %d" % len(roothash)

        sql_get_torrent_id = "SELECT torrent_id FROM Torrent WHERE swift_hash==?"
        tid = self._db.fetchone(sql_get_torrent_id, (bin2str(roothash),))
        return tid

    def getInfohash(self, torrent_id):
        sql_get_infohash = "SELECT infohash FROM Torrent WHERE torrent_id==?"
        ret = self._db.fetchone(sql_get_infohash, (torrent_id,))
        if ret:
            ret = str2bin(ret)
        return ret

    def hasTorrent(self, infohash):
        assert isinstance(infohash, str), "INFOHASH has invalid type: %s" % type(infohash)
        assert len(infohash) == INFOHASH_LENGTH, "INFOHASH has invalid length: %d" % len(infohash)
        if infohash in self.existed_torrents:  # to do: not thread safe
            return True
        infohash_str = bin2str(infohash)
        existed = self._db.getOne('CollectedTorrent', 'torrent_id', infohash=infohash_str)
        if existed is None:
            return False
        else:
            self.existed_torrents.add(infohash)
            return True

    def addExternalTorrent(self, torrentdef, source="BC", extra_info={}):
        assert isinstance(torrentdef, TorrentDef), "TORRENTDEF has invalid type: %s" % type(torrentdef)
        assert torrentdef.is_finalized(), "TORRENTDEF is not finalized"
        if torrentdef.is_finalized():
            infohash = torrentdef.get_infohash()
            if not self.hasTorrent(infohash):
                self._addTorrentToDB(torrentdef, source, extra_info)
                self.notifier.notify(NTFY_TORRENTS, NTFY_INSERT, infohash)

    def addExternalTorrentNoDef(self, infohash, name, files, trackers, timestamp, source, extra_info={}):
        if not self.hasTorrent(infohash):
            metainfo = {'info': {}, 'encoding': 'utf_8'}
            metainfo['info']['name'] = name.encode('utf_8')
            metainfo['info']['piece length'] = -1
            metainfo['info']['pieces'] = ''

            if len(files) > 1:
                files_as_dict = []
                for filename, file_lenght in files:
                    filename = filename.encode('utf_8')
                    files_as_dict.append({'path': [filename], 'length': file_lenght})
                metainfo['info']['files'] = files_as_dict

            elif len(files) == 1:
                metainfo['info']['length'] = files[0][1]
            else:
                return

            if len(trackers) > 0:
                metainfo['announce'] = trackers[0]
            else:
                metainfo['nodes'] = []

            metainfo['creation date'] = timestamp

            try:
                torrentdef = TorrentDef.load_from_dict(metainfo)
                torrentdef.infohash = infohash

                torrent_id = self._addTorrentToDB(torrentdef, source, extra_info)
                self._rtorrent_handler.notify_possible_torrent_infohash(infohash)

                insert_files = [(torrent_id, unicode(path), length) for path, length in files]
                if len(insert_files) > 0:
                    sql_insert_files = "INSERT OR IGNORE INTO TorrentFiles (torrent_id, path, length) VALUES (?,?,?)"
                    self._db.executemany(sql_insert_files, insert_files)

                magnetlink = u"magnet:?xt=urn:btih:" + hexlify(infohash)
                for tracker in trackers:
                    magnetlink += "&tr=" + urllib.quote_plus(tracker)
                insert_collecting = [(torrent_id, magnetlink)]

                if len(insert_collecting) > 0:
                    sql_insert_collecting = "INSERT OR IGNORE INTO TorrentCollecting (torrent_id, source) VALUES (?,?)"
                    self._db.executemany(sql_insert_collecting, insert_collecting)
            except:
                self._logger.error("Could not create a TorrentDef instance %s %s %s %s %s %s %s", infohash, timestamp, name, files, trackers, source, extra_info)
                print_exc()

    def addInfohash(self, infohash):
        assert isinstance(infohash, str), "INFOHASH has invalid type: %s" % type(infohash)
        assert len(infohash) == INFOHASH_LENGTH, "INFOHASH has invalid length: %d" % len(infohash)
        if self.getTorrentID(infohash) is None:
            status_id = self.misc_db.torrentStatusName2Id(u'unknown')
            self._db.insert_or_ignore('Torrent', infohash=bin2str(infohash), status_id=status_id)

    def addOrGetTorrentID(self, infohash):
        assert isinstance(infohash, str), "INFOHASH has invalid type: %s" % type(infohash)
        assert len(infohash) == INFOHASH_LENGTH, "INFOHASH has invalid length: %d" % len(infohash)

        torrent_id = self.getTorrentID(infohash)
        if torrent_id is None:
            status_id = self.misc_db.torrentStatusName2Id(u'unknown')
            self._db.insert('Torrent', infohash=bin2str(infohash), status_id=status_id)
            torrent_id = self.getTorrentID(infohash)
        return torrent_id

    def addOrGetTorrentIDRoot(self, roothash, name):
        assert isinstance(roothash, str), "roothash has invalid type: %s" % type(roothash)
        assert len(roothash) == INFOHASH_LENGTH, "roothash has invalid length: %d" % len(roothash)

        torrent_id = self.getTorrentIDRoot(roothash)
        if torrent_id is None:
            infohash = 'swift' + bin2str(roothash)[5:]
            status_id = self.misc_db.torrentStatusName2Id(u'unknown')
            self._db.insert('Torrent', infohash=infohash,
                swift_hash=bin2str(roothash), name=name, status_id=status_id)
            torrent_id = self.getTorrentIDRoot(roothash)
        return torrent_id

    def addOrGetTorrentIDS(self, infohashes):
        torrentIds, _ = self.addOrGetTorrentIDSReturn(infohashes)
        return torrentIds

    def addOrGetTorrentIDSReturn(self, infohashes):
        to_be_inserted = set()
        torrent_ids = self.getTorrentIDS(infohashes)
        for i in range(len(torrent_ids)):
            torrent_id = torrent_ids[i]
            if torrent_id is None:
                to_be_inserted.add(infohashes[i])

        status_id = self.misc_db.torrentStatusName2Id(u'unknown')
        sql = "INSERT INTO Torrent (infohash, status_id) VALUES (?, ?)"
        self._db.executemany(sql, [(bin2str(infohash), status_id) for infohash in to_be_inserted])

        torrent_ids = self.getTorrentIDS(infohashes)
        assert all(torrent_id for torrent_id in torrent_ids), torrent_ids
        return torrent_ids, to_be_inserted

    def _get_database_dict(self, torrentdef, source="BC", extra_info={}):
        assert isinstance(torrentdef, TorrentDef), "TORRENTDEF has invalid type: %s" % type(torrentdef)
        assert torrentdef.is_finalized(), "TORRENTDEF is not finalized"

        dict = {"infohash": bin2str(torrentdef.get_infohash()),
                "name": torrentdef.get_name_as_unicode(),
                "length": torrentdef.get_length(),
                "creation_date": torrentdef.get_creation_date(),
                "num_files": len(torrentdef.get_files()),
                "insert_time": long(time()),
                "secret": 1 if torrentdef.is_private() else 0,
                "relevance": 0.0,
                "source_id": self.misc_db.torrentSourceName2Id(source),
                # todo: the category_id is calculated directly from
                # torrentdef.metainfo, the category checker should use
                # the proper torrentdef api
                "category_id": self.misc_db.categoryName2Id(self.category.calculateCategory(torrentdef.metainfo, torrentdef.get_name_as_unicode())),
                "status_id": self.misc_db.torrentStatusName2Id(extra_info.get("status", "unknown")),
                "comment": torrentdef.get_comment_as_unicode()
                }

        if extra_info.get("filename", None):
            dict["torrent_file_name"] = extra_info["filename"]
        if extra_info.get("seeder", -1) != -1:
            dict["num_seeders"] = extra_info["seeder"]
        if extra_info.get("leecher", -1) != -1:
            dict["num_leechers"] = extra_info["leecher"]
        if extra_info.get('swift_hash', ''):
            dict['swift_hash'] = bin2str(extra_info['swift_hash'])
        if extra_info.get('swift_torrent_hash', ''):
            dict['swift_torrent_hash'] = bin2str(extra_info['swift_torrent_hash'])

        return dict

    def _addTorrentToDB(self, torrentdef, source, extra_info):
        assert isinstance(torrentdef, TorrentDef), "TORRENTDEF has invalid type: %s" % type(torrentdef)
        assert torrentdef.is_finalized(), "TORRENTDEF is not finalized"

        infohash = torrentdef.get_infohash()
        swarmname = torrentdef.get_name_as_unicode()
        database_dict = self._get_database_dict(torrentdef, source, extra_info)

        # see if there is already a torrent in the database with this infohash
        torrent_id = self.getTorrentID(infohash)
        if torrent_id is None:  # not in database
            self._db.insert("Torrent", **database_dict)
            torrent_id = self.getTorrentID(infohash)

        else:  # infohash in db
            del database_dict["infohash"]  # no need for infohash, its already stored
            where = "torrent_id = %d" % torrent_id
            self._db.update('Torrent', where=where, **database_dict)

        if not torrentdef.is_multifile_torrent():
            swarmname, _ = os.path.splitext(swarmname)
        self._indexTorrent(torrent_id, swarmname, torrentdef.get_files_as_unicode(), source in ['BC', 'SWIFT', 'DISP_SC'])

        self._addTorrentTracker(torrent_id, torrentdef, extra_info)
        return torrent_id

    def _indexTorrent(self, torrent_id, swarmname, files, collected):
        existed = self._db.getOne('CollectedTorrent', 'infohash', torrent_id=torrent_id)
        if existed and not collected:
            return

        # Niels: new method for indexing, replaces invertedindex
        # Making sure that swarmname does not include extension for single file torrents
        swarm_keywords = " ".join(split_into_keywords(swarmname, filterStopwords=False))

        filedict = {}
        fileextensions = set()
        for filename in files:
            filename, extension = os.path.splitext(filename)
            for keyword in split_into_keywords(filename, filterStopwords=True):
                filedict[keyword] = filedict.get(keyword, 0) + 1

            fileextensions.add(extension[1:])

        filenames = filedict.keys()
        if len(filenames) > 1000:
            def popSort(a, b):
                return filedict[a] - filedict[b]
            filenames.sort(cmp=popSort, reverse=True)
            filenames = filenames[:1000]

        values = (torrent_id, swarm_keywords, " ".join(filenames), " ".join(fileextensions))
        try:
            # INSERT OR REPLACE not working for fts3 table
            self._db.execute_write(u"DELETE FROM FullTextIndex WHERE rowid = ?", (torrent_id,))
            self._db.execute_write(u"INSERT INTO FullTextIndex (rowid, swarmname, filenames, fileextensions) VALUES(?,?,?,?)", values)
        except:
            # this will fail if the fts3 module cannot be found
            print_exc()

    # ------------------------------------------------------------
    # Adds the trackers of a given torrent into the database.
    # ------------------------------------------------------------
    def _addTorrentTracker(self, torrent_id, torrentdef, extra_info={}):
        # Set add_all to True if you want to put all multi-trackers into db.
        # In the current version (4.2) only the main tracker is used.

        announce = torrentdef.get_tracker()
        announce_list = torrentdef.get_tracker_hierarchy()

        # check if to use DHT
        new_tracker_set = set()
        if torrentdef.is_private():
            new_tracker_set.add('no-DHT')
        else:
            new_tracker_set.add('DHT')

        # get rid of junk trackers
        from Tribler.TrackerChecking.TrackerUtility import getUniformedURL
        # prepare the tracker list to add
        if announce:
            tracker_url = getUniformedURL(announce)
            if tracker_url:
                new_tracker_set.add(tracker_url)
        if announce_list:
            for tier in announce_list:
                for tracker in tier:
                    # TODO: check this. a limited tracker list
                    if len(new_tracker_set) >= 25:
                        break
                    tracker_url = getUniformedURL(tracker)
                    if tracker_url:
                        new_tracker_set.add(tracker_url)

        # add trackers in batch
        self.addTorrentTrackerMappingInBatch(torrent_id, list(new_tracker_set))

    def updateTorrent(self, infohash, notify=True, **kw):  # watch the schema of database
        if 'category' in kw:
            cat_id = self.misc_db.categoryName2Id(kw.pop('category'))
            kw['category_id'] = cat_id
        if 'status' in kw:
            status_id = self.misc_db.torrentStatusName2Id(kw.pop('status'))
            kw['status_id'] = status_id

        if 'progress' in kw:
            torrent_id = self.getTorrentID(infohash)
            if infohash:
                self.mypref_db.updateProgress(torrent_id, kw.pop('progress'))  # commit at end of function
        if 'seeder' in kw:
            kw['num_seeders'] = kw.pop('seeder')
        if 'leecher' in kw:
            kw['num_leechers'] = kw.pop('leecher')

        if 'swift_hash' in kw:
            kw['swift_hash'] = bin2str(kw['swift_hash'])

        if 'swift_torrent_hash' in kw:
            kw['swift_torrent_hash'] = bin2str(kw['swift_torrent_hash'])

        for key in kw.keys():
            if key not in self.keys:
                kw.pop(key)

        if len(kw) > 0:
            infohash_str = bin2str(infohash)
            where = "infohash='%s'" % infohash_str
            self._db.update(self.table_name, where, **kw)

        if notify:
            self.notifier.notify(NTFY_TORRENTS, NTFY_UPDATE, infohash)

    def on_torrent_collect_response(self, torrents):
        torrents = [(bin2str(torrent[0]), bin2str(torrent[1])) for torrent in torrents]

        infohashes = [infohash for infohash, _ in torrents if infohash]
        roothashes = [roothash for _, roothash in torrents if roothash]

        i_parameters = '?,' * len(infohashes)
        i_parameters = i_parameters[:-1]

        r_parameters = '?,' * len(roothashes)
        r_parameters = r_parameters[:-1]

        sql = "SELECT torrent_id, infohash, swift_torrent_hash FROM Torrent WHERE infohash in (" + i_parameters + ") or swift_torrent_hash in (" + r_parameters + ")"
        results = self._db.fetchall(sql, infohashes + roothashes)

        info_dict = {}
        root_dict = {}
        for torrent_id, infohash, roothash in results:
            if infohash.startswith('swift'):
                infohash = ''

            if infohash:
                info_dict[infohash] = torrent_id
            if roothash:
                root_dict[roothash] = torrent_id

        to_be_inserted = []
        update_infohash = []
        update_roothash = []
        for infohash, roothash in torrents:
            if infohash in info_dict and roothash in root_dict:
                continue
            elif infohash in info_dict:
                update_roothash.append((roothash, info_dict[infohash]))
            elif roothash in root_dict:
                update_infohash.append((infohash, root_dict[roothash]))
            else:
                to_be_inserted.append((infohash, roothash))

        if len(to_be_inserted) > 0:
            sql = "INSERT OR IGNORE INTO Torrent (infohash, swift_torrent_hash) VALUES (?, ?)"
            self._db.executemany(sql, to_be_inserted)

        if len(update_infohash) > 0:
            sql = "UPDATE Torrent SET infohash = ? WHERE torrent_id = ?"
            self._db.executemany(sql, update_infohash)

        if len(update_roothash) > 0:
            sql = "UPDATE Torrent SET swift_torrent_hash = ? WHERE torrent_id = ?"
            self._db.executemany(sql, update_roothash)

    def on_search_response(self, torrents):
        source_id = self.misc_db.torrentSourceName2Id(u'DISP_SEARCH')
        status_id = self.misc_db.torrentStatusName2Id(u'unknown')

        torrents = [(bin2str(torrent[0]), torrent[1], torrent[2], torrent[3], self.misc_db.categoryName2Id(torrent[4]), torrent[5], bin2str(torrent[8]) if torrent[8] else '', bin2str(torrent[9]) if torrent[9] else '') for torrent in torrents]
        info_root = [(torrent[0], torrent[6] or '--') for torrent in torrents]

        sql = "SELECT torrent_id, infohash, swift_hash, torrent_file_name, name FROM Torrent WHERE infohash = ? or swift_hash = ?"
        results = self._db.executemany(sql, info_root) or []

        infohash_tid = {}
        roothash_tid = {}

        tid_collected = set()
        tid_name = {}
        for torrent_id, infohash, roothash, torrent_filename, name in results:
            infohash = str(infohash)
            roothash = str(roothash)

            if infohash.startswith('swift'):
                infohash = ''

            if infohash:
                infohash_tid[infohash] = torrent_id
            if roothash:
                roothash_tid[roothash] = torrent_id
            if torrent_filename:
                tid_collected.add(torrent_id)
            tid_name[torrent_id] = name

        insert = []
        update = []
        update_roothash = []
        update_infohash = []
        to_be_indexed = []
        for infohash, swarmname, length, nrfiles, categoryid, creation_date, swift_hash, swift_torrent_hash in torrents:
            # 12/07/12 Boudewijn: swift_hash must be unique in the database, hence empty strings
            # must be stored as None
            if swift_hash == "":
                swift_hash = None
            # 02/08/12 Boudewijn: swift_torrent_hash has the same issue as swift_hash above
            if swift_torrent_hash == "":
                swift_torrent_hash = None

            tid = infohash_tid.get(infohash, None) or roothash_tid.get(swift_hash, None)

            if tid:  # we know this torrent
                if tid not in tid_collected and swarmname != tid_name.get(tid, ''):  # if not collected and name not equal then do fullupdate
                    update.append((swarmname, length, nrfiles, categoryid, creation_date, infohash, swift_hash, swift_torrent_hash, source_id, status_id, tid))
                    to_be_indexed.append((tid, swarmname))

                elif swift_hash and swift_hash not in roothash_tid:  # else check if we need to update swift
                    update_roothash.append((swift_hash, tid))

                elif infohash and infohash not in infohash_tid:  # or infohash
                    update_infohash.append((infohash, tid))
            else:
                insert.append((swarmname, length, nrfiles, categoryid, creation_date, infohash, swift_hash, swift_torrent_hash, source_id, status_id))

        if len(update) > 0:
            sql = "UPDATE Torrent SET name = ?, length = ?, num_files = ?, category_id = ?, creation_date = ?, infohash = ?, swift_hash = ?, swift_torrent_hash = ?, source_id = ?, status_id = ? WHERE torrent_id = ?"
            self._db.executemany(sql, update)

        if len(update_roothash) > 0:
            sql = "UPDATE Torrent SET swift_hash = ? WHERE torrent_id = ?"
            self._db.executemany(sql, update_roothash)

        if len(update_infohash) > 0:
            sql = "UPDATE Torrent SET infohash = ? WHERE torrent_id = ?"
            self._db.executemany(sql, update_infohash)

        if len(insert) > 0:
            sql = "INSERT INTO Torrent (name, length, num_files, category_id, creation_date, infohash, swift_hash, swift_torrent_hash, source_id, status_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            try:
                self._db.executemany(sql, insert)

                were_inserted = [(inserted[5], inserted[7]) for inserted in insert]
                sql = "SELECT torrent_id, name FROM Torrent WHERE infohash = ? or swift_hash = ?"
                to_be_indexed = to_be_indexed + list(self._db.executemany(sql, were_inserted))
            except:
                print_exc()
                self._logger.error("infohashes: %s", insert)

        for torrent_id, swarmname in to_be_indexed:
            self._indexTorrent(torrent_id, swarmname, [], False)

    def deleteTorrent(self, infohash, delete_file=False):
        if not self.hasTorrent(infohash):
            return False

        torrent_id = self.getTorrentID(infohash)
        if self.mypref_db.hasMyPreference(torrent_id):  # don't remove torrents in my pref
            return False

        if delete_file:
            deleted = self.eraseTorrentFile(infohash)
        else:
            deleted = True

        if deleted:
            self._deleteTorrent(infohash)

        self.notifier.notify(NTFY_TORRENTS, NTFY_DELETE, infohash)
        return deleted

    def _deleteTorrent(self, infohash, keep_infohash=True):
        torrent_id = self.getTorrentID(infohash)
        if torrent_id is not None:
            if keep_infohash:
                self._db.update(self.table_name, where="torrent_id=%d" % torrent_id, torrent_file_name=None)
            else:
                self._db.delete(self.table_name, torrent_id=torrent_id)
            if infohash in self.existed_torrents:
                self.existed_torrents.remove(infohash)

            self._db.delete('TorrentTrackerMapping', torrent_id=torrent_id)
            # print '******* delete torrent', torrent_id, `infohash`, self.hasTorrent(infohash)

    def eraseTorrentFile(self, infohash):
        torrent_id = self.getTorrentID(infohash)
        if torrent_id is not None:
            torrent_dir = self.getTorrentDir()
            torrent_name = self.getOne('torrent_file_name', torrent_id=torrent_id)
            src = os.path.join(torrent_dir, torrent_name)
            if not os.path.exists(src):  # already removed
                return True

            try:
                os.remove(src)
            except Exception as msg:
                self._logger.error("cachedbhandler: failed to erase torrent %s %s %s", src, Exception, msg)
                return False

        return True

    def getTorrentCheckRetries(self, torrent_id):
        sql = 'SELECT tracker_check_retries FROM Torrent WHERE torrent_id = ?'
        result = self._db.fetchone(sql, (torrent_id,))
        return result

    def updateTorrentCheckResult(self, torrent_id, infohash,
                seeders, leechers, last_check, next_check, status, retries):
        sql = 'UPDATE Torrent SET num_seeders = ?, num_leechers = ?'\
              + ', last_tracker_check = ?, next_tracker_check = ?'\
              + ', status_id = ?, tracker_check_retries = ?'\
              + ' WHERE torrent_id = ?'

        status_id = self.misc_db.torrentStatusName2Id(status)
        self._db.execute_write(sql,
            (seeders, leechers, last_check, next_check,
             status_id, retries, torrent_id))

        self._logger.debug("cachedbhandler: update result %d/%d for %s/%d", seeders, leechers, bin2str(infohash), torrent_id)

        # notify
        self.notifier.notify(NTFY_TORRENTS, NTFY_UPDATE, infohash)

    # ------------------------------------------------------------
    # Updates the TorrentTrackerMapping table.
    # ------------------------------------------------------------
    def addTorrentTrackerMapping(self, torrent_id, tracker):
        self.addTorrentTrackerMappingInBatch(torrent_id, [tracker, ])

    # ------------------------------------------------------------
    # Updates the TorrentTrackerMapping table in batch.
    # ------------------------------------------------------------
    def addTorrentTrackerMappingInBatch(self, torrent_id, tracker_list):
        if not tracker_list:
            return

        parameters = '?,' * len(tracker_list)
        sql = 'SELECT tracker FROM TrackerInfo WHERE tracker IN (' + parameters[:-1] + ')'
        found_tracker_list = self._db.fetchall(sql, tuple(tracker_list))
        found_tracker_list = [ tracker[0] for tracker in found_tracker_list ]

        # update tracker info
        not_found_tracker_list = [tracker for tracker in tracker_list if tracker not in found_tracker_list]
        if not_found_tracker_list:
            self.addTrackerInfoInBatch(not_found_tracker_list)

        # update torrent-tracker mapping
        sql = 'INSERT OR IGNORE INTO TorrentTrackerMapping(torrent_id, tracker_id)'\
            + ' VALUES(?, (SELECT tracker_id FROM TrackerInfo WHERE tracker = ?))'
        new_mapping_list = [(torrent_id, tracker) for tracker in tracker_list]
        if new_mapping_list:
            self._db.executemany(sql, new_mapping_list)

    # ------------------------------------------------------------
    # Gets all the torrents that has a specific tracker.
    # ------------------------------------------------------------
    def getTorrentsOnTracker(self, tracker, current_time):
        sql = """
            SELECT T.torrent_id, T.infohash, T.last_tracker_check
              FROM Torrent T, TrackerInfo TI, TorrentTrackerMapping TTM
              WHERE TI.tracker = ?
              AND TI.tracker_id = TTM.tracker_id AND T.torrent_id = TTM.torrent_id
              AND next_tracker_check < ?
            """
        infohash_list = self._db.fetchall(sql, (tracker, current_time))
        return [(torrent_id, str2bin(infohash), last_tracker_check) for torrent_id, infohash, last_tracker_check in infohash_list]

    # ------------------------------------------------------------
    # Gets a list of trackers of a given torrent ID.
    # (from TorrentTrackerMapping table)
    # ------------------------------------------------------------
    def getTrackerListByTorrentID(self, torrent_id):
        sql = 'SELECT TR.tracker FROM TrackerInfo TR, TorrentTrackerMapping MP'\
            + ' WHERE MP.torrent_id = ?'\
            + ' AND TR.tracker_id = MP.tracker_id'
        tracker_list = self._db.fetchall(sql, (torrent_id,))
        return [ tracker[0] for tracker in tracker_list ]

    # ------------------------------------------------------------
    # Gets a list of trackers of a given infohash.
    # (from TorrentTrackerMapping table)
    # ------------------------------------------------------------
    def getTrackerListByInfohash(self, infohash):
        torrent_id = self.getTorrentID(infohash)
        return self.getTrackerListByTorrentID(torrent_id)

    # ------------------------------------------------------------
    # Adds a new tracker into the TrackerInfo table.
    # ------------------------------------------------------------
    def addTrackerInfo(self, tracker, to_notify=True):
        self.addTrackerInfoInBatch([tracker, ], to_notify)

    # ------------------------------------------------------------
    # Adds a new trackers in batch into the TrackerInfo table.
    # ------------------------------------------------------------
    def addTrackerInfoInBatch(self, tracker_list, to_notify=True):
        sql = 'INSERT INTO TrackerInfo(tracker) VALUES(?)'
        self._db.executemany(sql, [(tracker,) for tracker in tracker_list])

        if to_notify:
            self.notifier.notify(NTFY_TRACKERINFO, NTFY_INSERT, tracker_list)

    # ------------------------------------------------------------
    # Gets all tracker information from the TrackerInfo table.
    # ------------------------------------------------------------
    def getTrackerInfoList(self):
        sql = 'SELECT tracker, last_check, failures, is_alive FROM TrackerInfo'
        tracker_info_list = self._db.fetchall(sql)
        return tracker_info_list

    # ------------------------------------------------------------
    # Updates a list of tracker status into the TrackerInfo table.
    # ------------------------------------------------------------
    def updateTrackerInfo(self, args):
        sql = 'UPDATE TrackerInfo SET'\
            + ' last_check = ?, failures = ?, is_alive = ?'\
            + ' WHERE tracker = ?'
        self._db.executemany(sql, args)

    # ------------------------------------------------------------
    # Gets a list of trackers that have been checked to be alive recently.
    # ------------------------------------------------------------
    def getRecentlyAliveTrackers(self, limit=10):
        sql = """
            SELECT DISTINCT tracker FROM TrackerInfo
              WHERE is_alive = 1
              AND tracker != 'no-DHT' AND tracker != 'DHT'
              ORDER BY last_check DESC LIMIT ?
            """
        trackers = self._db.fetchall(sql, (limit,))
        return [tracker[0] for tracker in trackers]

    def getTorrentDir(self):
        return self.torrent_dir

    def updateTorrentDir(self, torrent_dir):
        sql = "SELECT torrent_id, torrent_file_name FROM Torrent WHERE torrent_file_name not NULL"
        results = self._db.fetchall(sql)

        updates = []
        for result in results:
            head, tail = os.path.split(result[1])
            new_file_name = os.path.join(torrent_dir, tail)

            updates.append((new_file_name, result[0]))
        sql = "UPDATE TORRENT SET torrent_file_name = ? WHERE torrent_id = ?"
        self._db.executemany(sql, updates)

        self.torrent_dir = torrent_dir

    def getTorrent(self, infohash, keys=None, include_mypref=True):
        assert isinstance(infohash, str), "INFOHASH has invalid type: %s" % type(infohash)
        assert len(infohash) == INFOHASH_LENGTH, "INFOHASH has invalid length: %d" % len(infohash)
        # to do: replace keys like source -> source_id and status-> status_id ??

        if keys is None:
            keys = deepcopy(self.value_name)
        else:
            keys = list(keys)

        res = self._db.getOne('Torrent C', keys, infohash=bin2str(infohash))

        if not res:
            return None
        torrent = dict(zip(keys, res))
        if 'source_id' in torrent:
            torrent['source'] = self.misc_db.torrentSourceId2Name(torrent['source_id'])

        if 'category_id' in torrent:
            torrent['category'] = [self.misc_db.categoryId2Name(torrent['category_id'])]

        if 'status_id' in torrent:
            torrent['status'] = self.misc_db.torrentStatusId2Name(torrent['status_id'])

        if 'swift_hash' in torrent and torrent['swift_hash']:
            torrent['swift_hash'] = str2bin(torrent['swift_hash'])

        if 'swift_torrent_hash' in torrent and torrent['swift_torrent_hash']:
            torrent['swift_torrent_hash'] = str2bin(torrent['swift_torrent_hash'])

        torrent['infohash'] = infohash

        if include_mypref:
            tid = torrent['C.torrent_id']
            stats = self.mypref_db.getMyPrefStats(tid)

            if stats:
                torrent['myDownloadHistory'] = True
                torrent['creation_time'] = stats[tid][0]
                torrent['progress'] = stats[tid][1]
                torrent['destination_path'] = stats[tid][2]
            else:
                torrent['myDownloadHistory'] = False

        return torrent

    def getTorrents(self, category_name='all', range=None, library=False, sort=None, reverse=False):
        """
        get Torrents of some category and with alive status (opt. not in family filter)

        if library == True: only torrents with destination_path != '' are returned
        else: return only good torrents, accepted by family filter

        @return Returns a list of dicts with keys:
            torrent_id, infohash, name, category, status, creation_date, num_files, num_leechers, num_seeders,
            length, secret, insert_time, source, torrent_filename, relevance, simRank, tracker, last_check
            (if in library: myDownloadHistory, download_started, progress, dest_dir)

        niels 25-10-2010: changed behaviour to left join TorrentTracker, due to magnet links
        """

        # print >> sys.stderr, 'TorrentDBHandler: getTorrents(%s, %s, %s, %s, %s)' % (category_name, range, library, sort, reverse)
        s = time()

        value_name = deepcopy(self.value_name)
        sql = 'Select ' + ','.join(value_name)
        sql += ' From CollectedTorrent C'
        # sql += ' From CollectedTorrent C LEFT JOIN TorrentTrackerMapping TTM ON C.torrent_id = TTM.torrent_id'

        where = ''
        if category_name != 'all':
            category_id = self.misc_db._category_name2id_dict.get(category_name.lower(), -1)
            where += 'category_id = %d AND' % category_id  # unkown category_name returns no torrents

        if library:
            where += 'C.torrent_id in (select torrent_id from MyPreference where destination_path != "")'
        else:
            where += 'status_id=%d ' % self.misc_db.torrentStatusName2Id(u'good')  # if not library, show only good files
            where += self.category.get_family_filter_sql(self.misc_db.categoryName2Id)  # add familyfilter

        sql += ' Where ' + where

        if 'infohash' in value_name:
            sql += " GROUP BY infohash"

        if range:
            offset = range[0]
            limit = range[1] - range[0]
            sql += ' Limit %d Offset %d' % (limit, offset)

        if sort:
            # Arno, 2008-10-6: buggy: not reverse???
            desc = (reverse) and 'desc' or ''
            if sort == 'name':
                sql += ' Order By lower(%s) %s' % (sort, desc)
            else:
                sql += ' Order By %s %s' % (sort, desc)

        # print >>sys.stderr,"TorrentDBHandler: GET TORRENTS val",value_name,"where",where,"limit",limit,"offset",offset,"order",order_by
        # print_stack

        # Must come before query
        ranks = self.getRanks()
        res_list = self._db.fetchall(sql)
        mypref_stats = self.mypref_db.getMyPrefStats() if self.mypref_db else None

        torrent_list = self.valuelist2torrentlist(value_name, res_list, ranks, mypref_stats)
        del res_list
        del mypref_stats
        return torrent_list

    def getLibraryTorrents(self, keys):
        sql = "SELECT " + ", ".join(keys) + " FROM MyPreference, Torrent LEFT JOIN ChannelTorrents ON Torrent.torrent_id = ChannelTorrents.torrent_id WHERE destination_path != '' AND MyPreference.torrent_id = Torrent.torrent_id"
        data = self._db.fetchall(sql)

        fixed = self.__fixTorrents(keys, data)
        return fixed

    def valuelist2torrentlist(self, value_name, res_list, ranks, mypref_stats):
        torrent_list = []
        for item in res_list:
            value_name[0] = 'torrent_id'
            torrent = dict(zip(value_name, item))

            try:
                torrent['source'] = self.misc_db.torrentSourceId2Name(torrent['source_id'])
            except:
                print_exc()
                # Arno: RSS subscription and id2src issue
                torrent['source'] = 'http://some/RSS/feed'

            torrent['category'] = [self.misc_db.categoryId2Name(torrent['category_id'])]
            torrent['status'] = self.misc_db.torrentStatusId2Name(torrent['status_id'])
            torrent['simRank'] = ranksfind(ranks, torrent['infohash'])
            torrent['infohash'] = str2bin(torrent['infohash'])

            # Niels: we now convert category and status in gui
            # del torrent['category_id']
            # del torrent['status_id']
            torrent_id = torrent['torrent_id']
            if mypref_stats is not None and torrent_id in mypref_stats:
                # add extra info for torrent in mypref
                torrent['myDownloadHistory'] = True
                data = mypref_stats[torrent_id]  # (create_time,progress,destdir)
                torrent['download_started'] = data[0]
                torrent['progress'] = data[1]
                torrent['destdir'] = data[2]

            # print >>sys.stderr,"TorrentDBHandler: GET TORRENTS",`torrent`

            torrent_list.append(torrent)
        return torrent_list

    def __fixTorrents(self, keys, results):
        def fix_value(key):
            if key in keys:
                key_index = keys.index(key)
                for i in range(len(results)):
                    result = list(results[i])
                    if result[key_index]:
                        result[key_index] = str2bin(result[key_index])
                        results[i] = result
        fix_value('infohash')
        fix_value('swift_hash')
        fix_value('swift_torrent_hash')
        return results

    def getRanks(self):
        value_name = 'infohash'
        order_by = 'relevance desc'
        rankList_size = 20
        where = 'status_id=%d ' % self.misc_db.torrentStatusName2Id(u'good')
        res_list = self._db.getAll('Torrent', value_name, where=where, limit=rankList_size, order_by=order_by)
        return [a[0] for a in res_list]

    def getNumberCollectedTorrents(self):
        # return self._db.size('CollectedTorrent')
        return self._db.getOne('CollectedTorrent', 'count(torrent_id)')

    def getRecentlyCollectedSwiftHashes(self, limit=50):
        sql = """
            SELECT CT.swift_torrent_hash, CT.infohash, CT.num_seeders, CT.num_leechers, T.last_tracker_check, CT.insert_time
             FROM Torrent T, CollectedTorrent CT
             WHERE CT.torrent_id = T.torrent_id
             AND CT.swift_torrent_hash IS NOT NULL AND CT.swift_torrent_hash <> ''
             AND T.secret is not 1 ORDER BY CT.insert_time DESC LIMIT ?
             """
        results = self._db.fetchall(sql, (limit,))
        return [[str2bin(result[0]), str2bin(result[1]), result[2], result[3], result[4] or 0, result[5]] for result in results]

    def getRandomlyCollectedSwiftHashes(self, insert_time, limit=50):
        sql = """
            SELECT CT.swift_torrent_hash, CT.infohash, CT.num_seeders, CT.num_leechers, T.last_tracker_check
             FROM Torrent T, CollectedTorrent CT
             WHERE CT.torrent_id = T.torrent_id
             AND CT.insert_time < ?
             AND CT.swift_torrent_hash IS NOT NULL
             AND CT.swift_torrent_hash <> ''
             AND T.secret is not 1 ORDER BY RANDOM() DESC LIMIT ?
            """
        results = self._db.fetchall(sql, (insert_time, limit))
        return [[str2bin(result[0]), str2bin(result[1]), result[2], result[3], result[4] or 0] for result in results]

    def selectSwiftTorrentsToCollect(self, hashes):
        parameters = '?,' * len(hashes)
        parameters = parameters[:-1]

        # TODO: bias according to votecast, popular first

        sql = "SELECT infohash, swift_torrent_hash FROM Torrent WHERE torrent_file_name is NULL and infohash in (" + parameters + ")"
        results = self._db.fetchall(sql, map(bin2str, hashes))
        return [(str2bin(hash), str2bin(roothash)) for hash, roothash in results]

    def getTorrentsStats(self):
        return self._db.getOne('CollectedTorrent', ['count(torrent_id)', 'sum(length)', 'sum(num_files)'])

    def freeSpace(self, torrents2del):
# if torrents2del > 100:  # only delete so many torrents each time
#            torrents2del = 100
        if self.channelcast_db and self.channelcast_db._channel_id:
            sql = """
                select torrent_file_name, torrent_id, swift_torrent_hash, relevance,
                    min(relevance,2500) +  min(500,num_leechers) + 4*min(500,num_seeders) - (max(0,min(500,(%d-creation_date)/86400)) ) as weight
                from CollectedTorrent
                where torrent_id not in (select torrent_id from MyPreference)
                and torrent_id not in (select torrent_id from ChannelTorrents where channel_id = %d)
                order by weight
                limit %d
            """ % (int(time()), self.channelcast_db._channel_id, torrents2del)
        else:
            sql = """
                select torrent_file_name, torrent_id, swift_torrent_hash, relevance,
                    min(relevance,2500) +  min(500,num_leechers) + 4*min(500,num_seeders) - (max(0,min(500,(%d-creation_date)/86400)) ) as weight
                from CollectedTorrent
                where torrent_id not in (select torrent_id from MyPreference)
                order by weight
                limit %d
            """ % (int(time()), torrents2del)

        res_list = self._db.fetchall(sql)
        if len(res_list) == 0:
            return False

        # delete torrents from db
        sql_del_torrent = "update Torrent set torrent_file_name = null where torrent_id=?"
        # sql_del_tracker = "delete from TorrentTracker where torrent_id=?"
        # sql_del_pref = "delete from Preference where torrent_id=?"
        tids = [(torrent_id,) for torrent_file_name, torrent_id, swift_torrent_hash, relevance, weight in res_list]

        self._db.executemany(sql_del_torrent, tids)
        # self._db.executemany(sql_del_tracker, tids)
        # self._db.executemany(sql_del_pref, tids)

        # but keep the infohash in db to maintain consistence with preference db
        # torrent_id_infohashes = [(torrent_id,infohash_str,relevance) for torrent_file_name, torrent_id, infohash_str, relevance, weight in res_list]
        # sql_insert =  "insert into Torrent (torrent_id, infohash, relevance) values (?,?,?)"
        # self._db.executemany(sql_insert, torrent_id_infohashes)

        torrent_dir = self.getTorrentDir()
        deleted = 0  # deleted any file?
        insert_files = []
        for torrent_file_name, torrent_id, swift_torrent_hash, relevance, weight in res_list:

            torrent_path = os.path.join(torrent_dir, torrent_file_name)
            if not os.path.exists(torrent_path):
                roothash_as_hex = binascii.hexlify(swift_torrent_hash)
                torrent_path = os.path.join(torrent_dir, roothash_as_hex)

            if os.path.exists(torrent_path):
                try:
                    tdef = TorrentDef.load(torrent_path)
                    files = [(torrent_id, unicode(path), length) for path, length in tdef.get_files_as_unicode_with_length()]
                    files = sample(files, 25)
                    insert_files.extend(files)
                except:
                    pass

            mhash_path = torrent_path + '.mhash'
            mbinmap_path = torrent_path + '.mbinmap'
            try:
                if os.path.exists(torrent_path):
                    os.remove(torrent_path)

                if os.path.exists(mhash_path):
                    os.remove(mhash_path)

                if os.path.exists(mbinmap_path):
                    os.remove(mbinmap_path)

                deleted += 1
            except WindowsError:
                pass
            except Exception:
                print_exc()
                # print >> sys.stderr, "Error in erase torrent", Exception, msg
                pass

        if len(insert_files) > 0:
            sql_insert_files = "INSERT OR IGNORE INTO TorrentFiles (torrent_id, path, length) VALUES (?,?,?)"
            self._db.executemany(sql_insert_files, insert_files)

        self._logger.info("Erased %d torrents", deleted)
        return deleted

    def hasMetaData(self, infohash):
        return self.hasTorrent(infohash)

    def searchNames(self, kws, local=True, keys=['torrent_id', 'infohash', 'name', 'torrent_file_name', 'length', 'creation_date', 'num_files', 'insert_time', 'category_id', 'status_id', 'num_seeders', 'num_leechers', 'dispersy_id', 'swift_hash', 'swift_torrent_hash'], doSort=True):
        #        if local:
#            mainsql += "C.id, C.dispersy_id, C.name, C.description, C.time_stamp, inserted, "
#            value_name += ['channeltorrent_id', 'dispersy_id', 'chant_name', 'description', 'time_stamp', 'inserted']
#
        assert 'infohash' in keys
        assert not doSort or ('num_seeders' in keys or 'T.num_seeders' in keys)

        infohash_index = keys.index('infohash')
        swift_hash_index = keys.index('swift_hash') if 'swift_hash' in keys else -1
        swift_torrent_hash_index = keys.index('swift_torrent_hash') if 'swift_torrent_hash' in keys else -1
        num_seeders_index = keys.index('num_seeders') if 'num_seeders' in keys else -1

        if num_seeders_index == -1:
            doSort = False

        t1 = time()
        values = ", ".join(keys)
        mainsql = "SELECT " + values + ", C.channel_id, Matchinfo(FullTextIndex) FROM"
        if local:
            mainsql += " Torrent T"
        else:
            mainsql += " CollectedTorrent T"

        mainsql += """, FullTextIndex
                    LEFT OUTER JOIN _ChannelTorrents C ON T.torrent_id = C.torrent_id
                    WHERE t.torrent_id = FullTextIndex.rowid AND C.deleted_at IS NULL AND FullTextIndex MATCH ?
                    """

        if not local:
            mainsql += "AND T.secret is not 1 LIMIT 250"

        query = " ".join(filter_keywords(kws))
        not_negated = [kw for kw in filter_keywords(kws) if kw[0] != '-']

        results = self._db.fetchall(mainsql, (query,))

        t2 = time()

        channels = set()
        channel_dict = {}
        for result in results:
            if result[-2]:
                channels.add(result[-2])

        if len(channels) > 0:
            # Channels consist of a tuple (id, dispersy_cid, name, description, nr_torrents, nr_favorites, nr_spam, my_vote, modified)
            for channel in self.channelcast_db.getChannels(channels):
                if channel[1] != '-1':
                    channel_dict[channel[0]] = channel

        t3 = time()
        myChannelId = self.channelcast_db._channel_id or 0

        result_dict = {}

        # step 1, merge torrents keep one with best channel
        for result in results:
            channel_id = result[-2]
            channel = channel_dict.get(channel_id, False)

            infohash = result[infohash_index]
            if channel:
                # ignoring spam channels
                if channel[7] < 0:
                    continue

                # see if we have a better channel in torrents_dict
                if infohash in result_dict:
                    old_channel = channel_dict.get(result_dict[infohash][-2], False)
                    if old_channel:

                        # allways prefer my channel
                        if old_channel[0] == myChannelId:
                            continue

                        # allways prefer channel with higher vote
                        if channel[7] < old_channel[7]:
                            continue

                        votes = (channel[5] or 0) - (channel[6] or 0)
                        oldvotes = (old_channel[5] or 0) - (old_channel[6] or 0)
                        if votes < oldvotes:
                            continue

                result_dict[infohash] = result

            elif infohash not in result_dict:
                result_dict[infohash] = result

        t4 = time()

        # step 2, fix all dict fields
        dont_sort_list = []
        results = [list(result) for result in result_dict.values()]
        for i in xrange(len(results) - 1, -1, -1):
            result = results[i]

            result[infohash_index] = str2bin(result[infohash_index])
            if swift_hash_index >= 0 and result[swift_hash_index]:
                result[swift_hash_index] = str2bin(result[swift_hash_index])
            if swift_torrent_hash_index >= 0 and result[swift_torrent_hash_index]:
                result[swift_torrent_hash_index] = str2bin(result[swift_torrent_hash_index])

            matches = {'swarmname': set(), 'filenames': set(), 'fileextensions': set()}

            # Matchinfo is documented at: http://www.sqlite.org/fts3.html#matchinfo
            matchinfo = str(result[-1])
            num_phrases, num_cols = unpack_from('II', matchinfo)
            unpack_str = 'I' * (3 * num_cols * num_phrases)
            matchinfo = unpack_from('II' + unpack_str, matchinfo)

            swarmnames, filenames, fileextensions = [
                [matchinfo[3 * (i + p * num_cols) + 2] for p in range(num_phrases)]
                for i in range(num_cols)
            ]

            for i, keyword in enumerate(not_negated):
                if swarmnames[i]:
                    matches['swarmname'].add(keyword)
                if filenames[i]:
                    matches['filenames'].add(keyword)
                if fileextensions[i]:
                    matches['fileextensions'].add(keyword)
            result[-1] = matches

            channel = channel_dict.get(result[-2], (result[-2], None, '', '', 0, 0, 0, 0, 0, False))
            result.extend(channel)

            if doSort and result[num_seeders_index] <= 0:
                dont_sort_list.append(result)
                results.pop(i)

        t5 = time()

        if doSort:
            def compare(a, b):
                return cmp(a[num_seeders_index], b[num_seeders_index])
            results.sort(compare, reverse=True)
        results.extend(dont_sort_list)

        if not local:
            results = results[:25]

        # print >> sys.stderr, "# hits:%d (%d from db, %d not sorted); search time:%.3f,%.3f,%.3f,%.3f,%.3f,%.3f" % (len(results),len(results),len(dont_sort_list),t2-t1, t3-t2, t4-t3, t5-t4, time()-t5, time()-t1)
        return results

    def getAutoCompleteTerms(self, keyword, max_terms, limit=100):
        sql = "SELECT swarmname FROM FullTextIndex WHERE swarmname MATCH ? LIMIT ?"
        result = self._db.fetchall(sql, (keyword + '*', limit))

        all_terms = set()
        for line, in result:
            if len(all_terms) >= max_terms:
                break
            i1 = line.find(keyword)
            i2 = line.find(' ', i1 + len(keyword))
            all_terms.add(line[i1:i2] if i2 >= 0 else line[i1:])

        if keyword in all_terms:
            all_terms.remove(keyword)
        if '' in all_terms:
            all_terms.remove('')

        return list(all_terms)

    def getSearchSuggestion(self, keywords, limit=1):
        match = [keyword.lower() for keyword in keywords if len(keyword) > 3]

        def lev(a, b):
            "Calculates the Levenshtein distance between a and b."
            n, m = len(a), len(b)
            if n > m:
                # Make sure n <= m, to use O(min(n,m)) space
                a, b = b, a
                n, m = m, n

            current = range(n + 1)
            for i in range(1, m + 1):
                previous, current = current, [i] + [0] * n
                for j in range(1, n + 1):
                    add, delete = previous[j] + 1, current[j - 1] + 1
                    change = previous[j - 1]
                    if a[j - 1] != b[i - 1]:
                        change = change + 1
                    current[j] = min(add, delete, change)

            return current[n]

        def levcollate(s1, s2):
            l1 = sum(sorted([lev(a, b) for a in s1.split() for b in match])[:len(match)])
            l2 = sum(sorted([lev(a, b) for a in s2.split() for b in match])[:len(match)])

            # return -1 if s1<s2, +1 if s1>s2 else 0
            if l1 < l2:
                return -1
            if l1 > l2:
                return 1
            return 0

        cursor = self._db.getCursor()
        connection = cursor.getconnection()
        connection.createcollation("leven", levcollate)

        sql = "SELECT swarmname FROM FullTextIndex WHERE swarmname MATCH ? ORDER By swarmname collate leven ASC LIMIT ?"
        results = self._db.fetchall(sql, (' OR '.join(['*%s*' % m for m in match]), limit))
        connection.createcollation("leven", None)
        return [result[0] for result in results]

    def getTorrentFiles(self, torrent_id):
        sql = "SELECT path, length FROM TorrentFiles WHERE torrent_id = ?"
        return self._db.fetchall(sql, (torrent_id,))

    def getTorrentCollecting(self, torrent_id):
        sql = "SELECT source FROM TorrentCollecting WHERE torrent_id = ?"
        return self._db.fetchall(sql, (torrent_id,))

    def setSecret(self, infohash, secret):
        kw = {'secret': secret}
        self.updateTorrent(infohash, **kw)


class MyPreferenceDBHandler(BasicDBHandler):

    def __init__(self):
        if MyPreferenceDBHandler._single is not None:
            raise RuntimeError("MyPreferenceDBHandler is singleton")
        db = SQLiteCacheDB.getInstance()
        BasicDBHandler.__init__(self, db, 'MyPreference')  # # self,db,'MyPreference'

        self.status_good = MiscDBHandler.getInstance().torrentStatusName2Id(u'good')
        self.rlock = threading.RLock()
        self.loadData()

        self._torrent_db = TorrentDBHandler.getInstance()

    def loadData(self):
        """ Arno, 2010-02-04: Brute force update method for the self.recent_
        caches, because people don't seem to understand that caches need
        to be kept consistent with the database. Caches are evil in the first place.
        """
        self.recent_preflist = self.recent_preflist_with_clicklog = self.recent_preflist_with_swarmsize = None

    def getMyPrefList(self, order_by=None):
        res = self.getAll('torrent_id', order_by=order_by)
        return [p[0] for p in res]

    def getMyPrefListInfohash(self, returnDeleted=True, limit=None):
        # Arno, 2012-08-01: having MyPreference (the shorter list) first makes
        # this faster.
        sql = 'select infohash, swift_hash from MyPreference, Torrent where Torrent.torrent_id == MyPreference.torrent_id'
        if not returnDeleted:
            sql += ' AND destination_path != ""'

        if limit:
            sql += ' ORDER BY creation_time DESC LIMIT %d' % limit

        res = self._db.fetchall(sql)
        res = [item for sublist in res for item in sublist]
        return [str2bin(p) if p else '' for p in res]

    def getMyPrefStats(self, torrent_id=None):
        # get the full {torrent_id:(create_time,progress,destdir)}
        value_name = ('torrent_id', 'creation_time', 'progress', 'destination_path')
        if torrent_id is not None:
            where = 'torrent_id=%s' % torrent_id
        else:
            where = None
        res = self.getAll(value_name, where)
        mypref_stats = {}
        for pref in res:
            torrent_id, creation_time, progress, destination_path = pref
            mypref_stats[torrent_id] = (creation_time, progress, destination_path)
        return mypref_stats

    def getMyPrefStatsInfohash(self, infohash):
        torrent_id = self._torrent_db.getTorrentID(infohash)
        if torrent_id is not None:
            return self.getMyPrefStats(torrent_id)[torrent_id]

    def getRecentLivePrefList(self, num=0):
        if self.recent_preflist is None:
            self.rlock.acquire()
            try:
                if self.recent_preflist is None:
                    sql = """SELECT infohash from MyPreference m, Torrent t
                        WHERE m.torrent_id == t.torrent_id AND status_id == %d
                        ORDER BY creation_time DESC""" % self.status_good
                    recent_preflist = self._db.fetchall(sql)
                    self.recent_preflist = [str2bin(t[0]) for t in recent_preflist] if recent_preflist else []
            finally:
                self.rlock.release()
        if num > 0:
            return self.recent_preflist[:num]
        else:
            return self.recent_preflist

    def addClicklogToMyPreference(self, infohash, clicklog_data):
        torrent_id = self._torrent_db.getTorrentID(infohash)
        clicklog_already_stored = False  # equivalent to hasMyPreference TODO
        if torrent_id is None or clicklog_already_stored:
            return False

        d = {}
        # copy those elements of the clicklog data which are used in the update command
        for clicklog_key in ["click_position", "reranking_strategy"]:
            if clicklog_key in clicklog_data:
                d[clicklog_key] = clicklog_data[clicklog_key]

        if d == {}:
            self._logger.debug("no updatable information given to addClicklogToMyPreference")
        else:
            self._logger.debug("addClicklogToMyPreference: updatable clicklog data: %s", d)
            self._db.update(self.table_name, 'torrent_id=%d' % torrent_id, **d)

    def hasMyPreference(self, torrent_id):
        res = self.getOne('torrent_id', torrent_id=torrent_id)
        if res is not None:
            return True
        else:
            return False

    def addMyPreference(self, torrent_id, data):
        # keys in data: destination_path, progress, creation_time, torrent_id
        if self.hasMyPreference(torrent_id):
            # Arno, 2009-03-09: Torrent already exists in myrefs.
            # Hack for hiding from lib while keeping in myprefs.
            # see standardOverview.removeTorrentFromLibrary()
            #
            self.updateDestDir(torrent_id, data.get('destination_path'))
            infohash = self._torrent_db.getInfohash(torrent_id)
            if infohash:
                self.notifier.notify(NTFY_MYPREFERENCES, NTFY_UPDATE, infohash)
            return False

        d = {}
        d['destination_path'] = data.get('destination_path')
        d['progress'] = data.get('progress', 0)
        d['creation_time'] = data.get('creation_time', int(time()))
        d['torrent_id'] = torrent_id

        self._db.insert(self.table_name, **d)

        infohash = self._torrent_db.getInfohash(torrent_id)
        if infohash:
            self.notifier.notify(NTFY_MYPREFERENCES, NTFY_INSERT, infohash)

        # Arno, 2010-02-04: Update self.recent_ caches :-(
        # self.loadData()
        return True

    def deletePreference(self, torrent_id):
        # Preferences are never actually deleted from the database, only their destdirs get reset.
        #self._db.delete(self.table_name, **{'torrent_id': torrent_id})
        self.updateDestDir(torrent_id, "")

        infohash = self._torrent_db.getInfohash(torrent_id)
        if infohash:
            self.notifier.notify(NTFY_MYPREFERENCES, NTFY_DELETE, infohash)

        # Arno, 2010-02-04: Update self.recent_ caches :-(
        # self.loadData()

    def updateProgress(self, torrent_id, progress):
        self._db.update(self.table_name, 'torrent_id=%d' % torrent_id, progress=progress)

    def updateProgressByHash(self, hash, progress):
        torrent_id = self._torrent_db.getTorrentID(hash)
        if not torrent_id:
            torrent_id = self._torrent_db.getTorrentIDRoot(hash)

        if torrent_id:
            self.updateProgress(torrent_id, progress)

    def updateDestDir(self, torrent_id, destdir):
        if not isinstance(destdir, basestring):
            self._logger.info('DESTDIR IS NOT STRING: %s', destdir)
            return
        self._db.update(self.table_name, 'torrent_id=%d' % torrent_id, destination_path=destdir)


class VoteCastDBHandler(BasicDBHandler):

    def __init__(self):
        try:
            db = SQLiteCacheDB.getInstance()
            BasicDBHandler.__init__(self, db, 'VoteCast')
            self._logger.debug("votecast: DB made")
        except:
            self._logger.error("votecast: couldn't make the table")

        self.my_votes = None

        self.voteLock = Lock()
        self.updatedChannels = set()
        db.register_task("flush to database", LoopingCall(self._flush_to_database)).start(VOTECAST_FLUSH_DB_INTERVAL, now=False)

    def registerSession(self, session):
        self.session = session

        self.peer_db = PeerDBHandler.getInstance()
        self.channelcast_db = ChannelCastDBHandler.getInstance()

    def on_votes_from_dispersy(self, votes):
        insert_vote = "INSERT OR REPLACE INTO _ChannelVotes (channel_id, voter_id, dispersy_id, vote, time_stamp) VALUES (?,?,?,?,?)"
        self._db.executemany(insert_vote, votes)

        for channel_id, voter_id, _, _, _ in votes:
            if voter_id == None:
                self.notifier.notify(NTFY_VOTECAST, NTFY_UPDATE, channel_id, voter_id == None)
            self._scheduleUpdateChannelVotes(channel_id)

    def on_remove_votes_from_dispersy(self, votes, contains_my_vote):
        remove_vote = "UPDATE _ChannelVotes SET deleted_at = ? WHERE channel_id = ? AND dispersy_id = ?"
        self._db.executemany(remove_vote, votes)

        if contains_my_vote:
            for _, channel_id, _ in votes:
                self.notifier.notify(NTFY_VOTECAST, NTFY_UPDATE, channel_id, contains_my_vote)

        for _, channel_id, _ in votes:
            self._scheduleUpdateChannelVotes(channel_id)

    def _scheduleUpdateChannelVotes(self, channel_id):
        with self.voteLock:
            self.updatedChannels.add(channel_id)

    def _flush_to_database(self):
        with self.voteLock:
            channel_ids = list(self.updatedChannels)
            self.updatedChannels.clear()

        if channel_ids:
            parameters = ",".join("?" * len(channel_ids))
            sql = "Select channel_id, vote FROM ChannelVotes WHERE channel_id in (" + parameters + ")"
            positive_votes = {}
            negative_votes = {}
            for channel_id, vote in self._db.fetchall(sql, channel_ids):
                if vote == 2:
                    positive_votes[channel_id] = positive_votes.get(channel_id, 0) + 1
                elif vote == -1:
                    negative_votes[channel_id] = negative_votes.get(channel_id, 0) + 1

            updates = [(positive_votes.get(channel_id, 0), negative_votes.get(channel_id, 0), channel_id) for channel_id in channel_ids]
            self._db.executemany("UPDATE OR IGNORE _Channels SET nr_favorite = ?, nr_spam = ? WHERE id = ?", updates)

            for channel_id in channel_ids:
                self.notifier.notify(NTFY_VOTECAST, NTFY_UPDATE, channel_id)

    def get_latest_vote_dispersy_id(self, channel_id, voter_id):
        if voter_id:
            select_vote = "SELECT dispersy_id FROM ChannelVotes WHERE channel_id = ? AND voter_id = ? AND dispersy_id != -1 ORDER BY time_stamp DESC Limit 1"
            return self._db.fetchone(select_vote, (channel_id, voter_id))

        select_vote = "SELECT dispersy_id FROM ChannelVotes WHERE channel_id = ? AND voter_id ISNULL AND dispersy_id != -1 ORDER BY time_stamp DESC Limit 1"
        return self._db.fetchone(select_vote, (channel_id,))

    def getPosNegVotes(self, channel_id):
        sql = 'select nr_favorite, nr_spam from Channels where id = ?'
        result = self._db.fetchone(sql, (channel_id,))
        if result:
            return result
        return 0, 0

    def getVoteOnChannel(self, channel_id, voter_id):
        """ return the vote status if such record exists, otherwise None  """
        if voter_id:
            sql = "select vote from ChannelVotes where channel_id = ? and voter_id = ?"
            return self._db.fetchone(sql, (channel_id, voter_id))
        sql = "select vote from ChannelVotes where channel_id = ? and voter_id ISNULL"
        return self._db.fetchone(sql, (channel_id,))

    def getVoteForMyChannel(self, voter_id):
        return self.getVoteOnChannel(self.channelcast_db._channel_id, voter_id)

    def getDispersyId(self, channel_id, voter_id):
        """ return the dispersy_id for this vote """
        if voter_id:
            sql = "select dispersy_id from ChannelVotes where channel_id = ? and voter_id = ?"
            return self._db.fetchone(sql, (channel_id, voter_id))
        sql = "select dispersy_id from ChannelVotes where channel_id = ? and voter_id ISNULL"
        return self._db.fetchone(sql, (channel_id,))

    def getTimestamp(self, channel_id, voter_id):
        """ return the timestamp for this vote """
        if voter_id:
            sql = "select time_stamp from ChannelVotes where channel_id = ? and voter_id = ?"
            return self._db.fetchone(sql, (channel_id, voter_id))
        sql = "select time_stamp from ChannelVotes where channel_id = ? and voter_id ISNULL"
        return self._db.fetchone(sql, (channel_id,))

    def getMyVotes(self):
        if not self.my_votes:
            sql = "SELECT channel_id, vote FROM ChannelVotes WHERE voter_id ISNULL"

            self.my_votes = {}
            for channel_id, vote in self._db.fetchall(sql):
                self.my_votes[channel_id] = vote
        return self.my_votes


class ChannelCastDBHandler(BasicDBHandler):

    def __init__(self):
        try:
            db = SQLiteCacheDB.getInstance()
            BasicDBHandler.__init__(self, db, '_Channels')
            self._logger.debug("Channels: DB made")
        except:
            self._logger.error("Channels: couldn't make the table")

        self._channel_id = None
        self.my_dispersy_cid = None

        self.modification_types = dict(self._db.fetchall("SELECT name, id FROM MetaDataTypes"))
        self.id2modification = dict([(v, k) for k, v in self.modification_types.iteritems()])

        self._channel_id = self.getMyChannelId()
        self._logger.debug("Channels: my channel is %s", self._channel_id)

    def registerSession(self, session):
        self.session = session

        self.peer_db = PeerDBHandler.getInstance()
        self.votecast_db = VoteCastDBHandler.getInstance()
        self.torrent_db = TorrentDBHandler.getInstance()

        def updateNrTorrents():
            rows = self.getChannelNrTorrents(50)
            update = "UPDATE _Channels SET nr_torrents = ? WHERE id = ?"
            self._db.executemany(update, rows)

            rows = self.getChannelNrTorrentsLatestUpdate(50)
            update = "UPDATE _Channels SET nr_torrents = ?, modified = ? WHERE id = ?"
            self._db.executemany(update, rows)

        self.register_task("updateNrTorrents", LoopingCall(updateNrTorrents)).start(300, now=False)

    # dispersy helper functions
    def _get_my_dispersy_cid(self):
        if not self.my_dispersy_cid:
            from Tribler.community.channel.community import ChannelCommunity

            for community in self.session.lm.dispersy.get_communities():
                if isinstance(community, ChannelCommunity) and community.master_member and community.master_member.private_key:
                    self.my_dispersy_cid = community.cid
                    break

        return self.my_dispersy_cid

    def getDispersyCIDFromChannelId(self, channel_id):
        return self._db.fetchone(u"SELECT dispersy_cid FROM Channels WHERE id = ?", (channel_id,))

    def getChannelIdFromDispersyCID(self, dispersy_cid):
        return self._db.fetchone(u"SELECT id FROM Channels WHERE dispersy_cid = ?", (dispersy_cid,))

    def getCountMaxFromChannelId(self, channel_id):
        sql = u"SELECT COUNT(*), MAX(inserted) FROM ChannelTorrents WHERE channel_id = ? LIMIT 1"
        return self._db.fetchone(sql, (channel_id,))

    def drop_all_newer(self, dispersy_id):
        sql = "DELETE FROM _TorrentMarkings WHERE dipsersy_id > ?"
        self._db.execute_write(sql, (dispersy_id))

        sql = "DELETE FROM _ChannelVotes WHERE dipsersy_id > ?"
        self._db.execute_write(sql, (dispersy_id))

        sql = "DELETE FROM _ChannelMetaData WHERE dipsersy_id > ?"
        self._db.execute_write(sql, (dispersy_id))

        sql = "DELETE FROM _Moderations WHERE dipsersy_id > ?"
        self._db.execute_write(sql, (dispersy_id))

        sql = "DELETE FROM _Comments WHERE dipsersy_id > ?"
        self._db.execute_write(sql, (dispersy_id))

        sql = "DELETE FROM _PlaylistTorrents WHERE dipsersy_id > ?"
        self._db.execute_write(sql, (dispersy_id))

        sql = "DELETE FROM _Playlists WHERE dipsersy_id > ?"
        self._db.execute_write(sql, (dispersy_id))

        sql = "DELETE FROM _ChannelTorrents WHERE dipsersy_id > ?"
        self._db.execute_write(sql, (dispersy_id))

    def on_channel_from_dispersy(self, dispersy_cid, peer_id, name, description):
        if isinstance(dispersy_cid, (str)):
            _dispersy_cid = buffer(dispersy_cid)
        else:
            _dispersy_cid = dispersy_cid

        # merge channels if we detect upgrade from old-channelcast to new-dispersy-channelcast
        get_channel = "SELECT id FROM Channels Where peer_id = ? and dispersy_cid == -1"
        channel_id = self._db.fetchone(get_channel, (peer_id,))

        if channel_id:  # update this channel
            update_channel = "UPDATE _Channels SET dispersy_cid = ?, name = ?, description = ? WHERE id = ?"
            self._db.execute_write(update_channel, (_dispersy_cid, name, description, channel_id))

            self.notifier.notify(NTFY_CHANNELCAST, NTFY_UPDATE, channel_id)

        else:
            get_channel = "SELECT id FROM Channels Where dispersy_cid = ?"
            channel_id = self._db.fetchone(get_channel, (_dispersy_cid,))

            if channel_id:
                update_channel = "UPDATE _Channels SET name = ?, description = ?, peer_id = ? WHERE dispersy_cid = ?"
                self._db.execute_write(update_channel, (name, description, peer_id, _dispersy_cid))

            else:
                # insert channel
                insert_channel = "INSERT INTO _Channels (dispersy_cid, peer_id, name, description) VALUES (?, ?, ?, ?); SELECT last_insert_rowid();"
                channel_id = self._db.fetchone(insert_channel, (_dispersy_cid, peer_id, name, description))

            self.notifier.notify(NTFY_CHANNELCAST, NTFY_INSERT, channel_id)

        if not self._channel_id and self._get_my_dispersy_cid() == dispersy_cid:
            self._channel_id = channel_id
            self.notifier.notify(NTFY_CHANNELCAST, NTFY_CREATE, channel_id)
        return channel_id

    def on_channel_modification_from_dispersy(self, channel_id, modification_type, modification_value):
        if modification_type in ['name', 'description']:
            update_channel = "UPDATE _Channels Set " + modification_type + " = ?, modified = ? WHERE id = ?"
            self._db.execute_write(update_channel, (modification_value, long(time()), channel_id))

            self.notifier.notify(NTFY_CHANNELCAST, NTFY_MODIFIED, channel_id)

    def on_torrents_from_dispersy(self, torrentlist):
        infohashes = [torrent[3] for torrent in torrentlist]
        torrent_ids, inserted = self.torrent_db.addOrGetTorrentIDSReturn(infohashes)

        insert_data = []
        updated_channels = {}
        for i, torrent in enumerate(torrentlist):
            channel_id, dispersy_id, peer_id, infohash, timestamp, name, files, trackers = torrent
            torrent_id = torrent_ids[i]

            # if new or not yet collected
            if infohash in inserted:
                self.torrent_db.addExternalTorrentNoDef(infohash, name, files, trackers, timestamp, "DISP", {'dispersy_id': dispersy_id})

            insert_data.append((dispersy_id, torrent_id, channel_id, peer_id, name, timestamp))
            updated_channels[channel_id] = updated_channels.get(channel_id, 0) + 1

        if len(insert_data) > 0:
            sql_insert_torrent = "INSERT INTO _ChannelTorrents (dispersy_id, torrent_id, channel_id, peer_id, name, time_stamp) VALUES (?,?,?,?,?,?)"
            self._db.executemany(sql_insert_torrent, insert_data)

        sql_update_channel = "UPDATE _Channels SET modified = strftime('%s','now'), nr_torrents = nr_torrents+? WHERE id = ?"
        update_channels = [(new_torrents, channel_id) for channel_id, new_torrents in updated_channels.iteritems()]
        self._db.executemany(sql_update_channel, update_channels)

        for channel_id in updated_channels.keys():
            self.notifier.notify(NTFY_CHANNELCAST, NTFY_UPDATE, channel_id)

    def on_remove_torrent_from_dispersy(self, channel_id, dispersy_id, redo):
        sql = "UPDATE _ChannelTorrents SET deleted_at = ? WHERE channel_id = ? and dispersy_id = ?"

        if redo:
            deleted_at = None
        else:
            deleted_at = long(time())
        self._db.execute_write(sql, (deleted_at, channel_id, dispersy_id))

        self.notifier.notify(NTFY_CHANNELCAST, NTFY_UPDATE, channel_id)

    def on_torrent_modification_from_dispersy(self, channeltorrent_id, modification_type, modification_value):
        if modification_type in ['name', 'description']:
            update_torrent = "UPDATE _ChannelTorrents SET " + modification_type + " = ?, modified = ? WHERE id = ?"
            self._db.execute_write(update_torrent, (modification_value, long(time()), channeltorrent_id))

            sql = "Select infohash From Torrent, ChannelTorrents Where Torrent.torrent_id = ChannelTorrents.torrent_id And ChannelTorrents.id = ?"
            infohash = self._db.fetchone(sql, (channeltorrent_id,))

            if infohash:
                infohash = str2bin(infohash)
                self.notifier.notify(NTFY_TORRENTS, NTFY_UPDATE, infohash)

        elif modification_type in ['swift-url']:
            sql = "Select infohash From Torrent, ChannelTorrents Where Torrent.torrent_id = ChannelTorrents.torrent_id And ChannelTorrents.id = ?"
            infohash = self._db.fetchone(sql, (channeltorrent_id,))

            if infohash:
                from Tribler.Core.Swift.SwiftDef import SwiftDef

                sdef = SwiftDef.load_from_url(modification_value)
                roothash = bin2str(sdef.get_roothash())
                # If a user created two .torrents from the same set of files with different swarmnames we have two infohashes pointing to the same roothash.
                update_torrent = "UPDATE or IGNORE Torrent SET swift_hash = ? WHERE infohash = ?"
                self._db.execute_write(update_torrent, (roothash, infohash))

    def addOrGetChannelTorrentID(self, channel_id, infohash):
        torrent_id = self.torrent_db.addOrGetTorrentID(infohash)

        sql = "SELECT id FROM _ChannelTorrents WHERE torrent_id = ? AND channel_id = ?"
        channeltorrent_id = self._db.fetchone(sql, (torrent_id, channel_id))
        if not channeltorrent_id:
            insert_torrent = "INSERT OR IGNORE INTO _ChannelTorrents (dispersy_id, torrent_id, channel_id, time_stamp) VALUES (?,?,?,?);"
            self._db.execute_write(insert_torrent, (-1, torrent_id, channel_id, -1))

            channeltorrent_id = self._db.fetchone(sql, (torrent_id, channel_id))
        return channeltorrent_id

    def hasTorrent(self, channel_id, infohash):
        torrent_id = self.torrent_db.getTorrentID(infohash)
        if torrent_id:
            sql = "SELECT id FROM ChannelTorrents WHERE torrent_id = ? and channel_id = ?"
            channeltorrent_id = self._db.fetchone(sql, (torrent_id, channel_id))
            if channeltorrent_id:
                return True
        return False

    def hasTorrents(self, channel_id, infohashes):
        returnAr = []
        torrent_ids = self.torrent_db.getTorrentIDS(infohashes)

        for i in range(len(infohashes)):
            if torrent_ids[i] == None:
                returnAr.append(False)

            else:
                sql = "SELECT id FROM ChannelTorrents WHERE torrent_id = ? AND channel_id = ? AND dispersy_id <> -1"
                channeltorrent_id = self._db.fetchone(sql, (torrent_ids[i], channel_id))
                returnAr.append(True if channeltorrent_id else False)
        return returnAr

    def playlistHasTorrent(self, playlist_id, channeltorrent_id):
        sql = "SELECT id FROM PlaylistTorrents WHERE playlist_id = ? AND channeltorrent_id = ?"
        playlisttorrent_id = self._db.fetchone(sql, (playlist_id, channeltorrent_id))
        if playlisttorrent_id:
            return True
        return False

    # dispersy receiving comments
    def on_comment_from_dispersy(self, channel_id, dispersy_id, mid_global_time, peer_id, comment, timestamp, reply_to, reply_after, playlist_dispersy_id, infohash):
        # both reply_to and reply_after could be loose pointers to not yet received dispersy message
        if isinstance(reply_to, (str)):
            reply_to = buffer(reply_to)

        if isinstance(reply_after, (str)):
            reply_after = buffer(reply_after)
        mid_global_time = buffer(mid_global_time)

        sql = "INSERT OR REPLACE INTO _Comments (channel_id, dispersy_id, peer_id, comment, reply_to_id, reply_after_id, time_stamp) VALUES (?, ?, ?, ?, ?, ?, ?); SELECT last_insert_rowid();"
        comment_id = self._db.fetchone(sql, (channel_id, dispersy_id, peer_id, comment, reply_to, reply_after, timestamp))

        if playlist_dispersy_id or infohash:
            if playlist_dispersy_id:
                sql = "SELECT id FROM Playlists WHERE dispersy_id = ?"
                playlist_id = self._db.fetchone(sql, (playlist_dispersy_id,))

                sql = "INSERT INTO CommentPlaylist (comment_id, playlist_id) VALUES (?, ?)"
                self._db.execute_write(sql, (comment_id, playlist_id))

            if infohash:
                channeltorrent_id = self.addOrGetChannelTorrentID(channel_id, infohash)

                sql = "INSERT INTO CommentTorrent (comment_id, channeltorrent_id) VALUES (?, ?)"
                self._db.execute_write(sql, (comment_id, channeltorrent_id))

        # try fo fix loose reply_to and reply_after pointers
        sql = "UPDATE _Comments SET reply_to_id = ? WHERE reply_to_id = ?"
        self._db.execute_write(sql, (dispersy_id, mid_global_time))
        sql = "UPDATE _Comments SET reply_after_id = ? WHERE reply_after_id = ?"
        self._db.execute_write(sql, (dispersy_id, mid_global_time))

        self.notifier.notify(NTFY_COMMENTS, NTFY_INSERT, channel_id)
        if playlist_dispersy_id:
            self.notifier.notify(NTFY_COMMENTS, NTFY_INSERT, playlist_id)
        if infohash:
            self.notifier.notify(NTFY_COMMENTS, NTFY_INSERT, infohash)

    # dispersy removing comments
    def on_remove_comment_from_dispersy(self, channel_id, dispersy_id, infohash=None, redo=False):
        sql = "UPDATE _Comments SET deleted_at = ? WHERE dispersy_id = ?"

        if redo:
            deleted_at = None
            self._db.execute_write(sql, (deleted_at, dispersy_id))

            self.notifier.notify(NTFY_COMMENTS, NTFY_INSERT, channel_id)
            if infohash:
                self.notifier.notify(NTFY_COMMENTS, NTFY_INSERT, infohash)
        else:
            deleted_at = long(time())
            self._db.execute_write(sql, (deleted_at, dispersy_id))

            self.notifier.notify(NTFY_COMMENTS, NTFY_DELETE, channel_id)
            if infohash:
                self.notifier.notify(NTFY_COMMENTS, NTFY_DELETE, infohash)

    # dispersy receiving, modifying playlists
    def on_playlist_from_dispersy(self, channel_id, dispersy_id, peer_id, name, description):
        sql = "INSERT OR REPLACE INTO _Playlists (channel_id, dispersy_id,  peer_id, name, description) VALUES (?, ?, ?, ?, ?)"
        self._db.execute_write(sql, (channel_id, dispersy_id, peer_id, name, description))

        self.notifier.notify(NTFY_PLAYLISTS, NTFY_INSERT, channel_id)

    def on_remove_playlist_from_dispersy(self, channel_id, dispersy_id, redo):
        sql = "UPDATE _Playlists SET deleted_at = ? WHERE channel_id = ? and dispersy_id = ?"

        if redo:
            deleted_at = None
            self._db.execute_write(sql, (deleted_at, channel_id, dispersy_id))
            self.notifier.notify(NTFY_PLAYLISTS, NTFY_INSERT, channel_id)

        else:
            deleted_at = long(time())
            self._db.execute_write(sql, (deleted_at, channel_id, dispersy_id))
            self.notifier.notify(NTFY_PLAYLISTS, NTFY_DELETE, channel_id)

    def on_playlist_modification_from_dispersy(self, playlist_id, modification_type, modification_value):
        if modification_type in ['name', 'description']:
            update_playlist = "UPDATE _Playlists Set " + modification_type + " = ?, modified = ? WHERE id = ?"
            self._db.execute_write(update_playlist, (modification_value, long(time()), playlist_id))

            self.notifier.notify(NTFY_PLAYLISTS, NTFY_UPDATE, playlist_id)

    def on_playlist_torrent(self, dispersy_id, playlist_dispersy_id, peer_id, infohash):
        get_playlist = "SELECT id, channel_id FROM _Playlists WHERE dispersy_id = ?"
        playlist_id, channel_id = self._db.fetchone(get_playlist, (playlist_dispersy_id,))

        channeltorrent_id = self.addOrGetChannelTorrentID(channel_id, infohash)
        sql = "INSERT INTO _PlaylistTorrents (dispersy_id, playlist_id, peer_id, channeltorrent_id) VALUES (?,?,?,?)"
        self._db.execute_write(sql, (dispersy_id, playlist_id, peer_id, channeltorrent_id))

        self.notifier.notify(NTFY_PLAYLISTS, NTFY_UPDATE, playlist_id, infohash)

    def on_remove_playlist_torrent(self, channel_id, playlist_dispersy_id, infohash, redo):
        get_playlist = "SELECT id FROM _Playlists WHERE dispersy_id = ? AND channel_id = ?"
        playlist_id = self._db.fetchone(get_playlist, (playlist_dispersy_id, channel_id))

        if playlist_id:
            get_channeltorent_id = "SELECT id FROM _ChannelTorrents, Torrent WHERE _ChannelTorrents.torrent_id = Torrent.torrent_id AND Torrent.infohash = ?"
            channeltorrent_id = self._db.fetchone(get_channeltorent_id, (bin2str(infohash),))

            if channeltorrent_id:
                sql = "UPDATE _PlaylistTorrents SET deleted_at = ? WHERE playlist_id = ? AND channeltorrent_id = ?"

                if redo:
                    deleted_at = None
                else:
                    deleted_at = long(time())
                self._db.execute_write(sql, (deleted_at, playlist_id, channeltorrent_id))

            self.notifier.notify(NTFY_PLAYLISTS, NTFY_UPDATE, playlist_id)

    def on_metadata_from_dispersy(self, type, channeltorrent_id, playlist_id, channel_id, dispersy_id, peer_id, mid_global_time, modification_type_id, modification_value, timestamp, prev_modification_id, prev_modification_global_time):
        if isinstance(prev_modification_id, (str)):
            prev_modification_id = buffer(prev_modification_id)

        sql = "INSERT OR REPLACE INTO _ChannelMetaData (dispersy_id, channel_id, peer_id, type_id, value, time_stamp, prev_modification, prev_global_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?); SELECT last_insert_rowid();"
        metadata_id = self._db.fetchone(sql, (dispersy_id, channel_id, peer_id, modification_type_id, modification_value, timestamp, prev_modification_id, prev_modification_global_time))

        if channeltorrent_id:
            sql = "INSERT INTO MetaDataTorrent (metadata_id, channeltorrent_id) VALUES (?,?)"
            self._db.execute_write(sql, (metadata_id, channeltorrent_id))

            self.notifier.notify(NTFY_MODIFICATIONS, NTFY_INSERT, channeltorrent_id)

        if playlist_id:
            sql = "INSERT INTO MetaDataPlaylist (metadata_id, playlist_id) VALUES (?,?)"
            self._db.execute_write(sql, (metadata_id, playlist_id))

            self.notifier.notify(NTFY_MODIFICATIONS, NTFY_INSERT, playlist_id)
        self.notifier.notify(NTFY_MODIFICATIONS, NTFY_INSERT, channel_id)

        # try fo fix loose reply_to and reply_after pointers
        sql = "UPDATE _ChannelMetaData SET prev_modification = ? WHERE prev_modification = ?;"
        self._db.execute_write(sql, (dispersy_id, buffer(mid_global_time)))

    def on_remove_metadata_from_dispersy(self, channel_id, dispersy_id, redo):
        sql = "UPDATE _ChannelMetaData SET deleted_at = ? WHERE dispersy_id = ? AND channel_id = ?"

        if redo:
            deleted_at = None
        else:
            deleted_at = long(time())
        self._db.execute_write(sql, (deleted_at, dispersy_id, channel_id))

    def on_moderation(self, channel_id, dispersy_id, peer_id, by_peer_id, cause, message, timestamp, severity):
        sql = "INSERT OR REPLACE INTO _Moderations (dispersy_id, channel_id, peer_id, by_peer_id, message, cause, time_stamp, severity) VALUES (?,?,?,?,?,?,?,?)"
        self._db.execute_write(sql, (dispersy_id, channel_id, peer_id, by_peer_id, message, cause, timestamp, severity))

        self.notifier.notify(NTFY_MODERATIONS, NTFY_INSERT, channel_id)

    def on_remove_moderation(self, channel_id, dispersy_id, redo):
        sql = "UPDATE _Moderations SET deleted_at = ? WHERE dispersy_id = ? AND channel_id = ?"
        if redo:
            deleted_at = None
        else:
            deleted_at = long(time())
        self._db.execute_write(sql, (deleted_at, dispersy_id, channel_id))

    def on_mark_torrent(self, channel_id, dispersy_id, global_time, peer_id, infohash, type, timestamp):
        channeltorrent_id = self.addOrGetChannelTorrentID(channel_id, infohash)

        if peer_id:
            select = "SELECT global_time FROM TorrentMarkings WHERE channeltorrent_id = ? AND peer_id = ?"
            prev_global_time = self._db.fetchone(select, (channeltorrent_id, peer_id))
        else:
            select = "SELECT global_time FROM TorrentMarkings WHERE channeltorrent_id = ? AND peer_id IS NULL"
            prev_global_time = self._db.fetchone(select, (channeltorrent_id,))

        if prev_global_time:
            if global_time > prev_global_time:
                if peer_id:
                    sql = "DELETE FROM _TorrentMarkings WHERE channeltorrent_id = ? AND peer_id = ?"
                    self._db.execute_write(sql, (channeltorrent_id, peer_id))
                else:
                    sql = "DELETE FROM _TorrentMarkings WHERE channeltorrent_id = ? AND peer_id IS NULL"
                    self._db.execute_write(sql, (channeltorrent_id,))
            else:
                return

        sql = "INSERT INTO _TorrentMarkings (dispersy_id, global_time, channeltorrent_id, peer_id, type, time_stamp) VALUES (?,?,?,?,?,?)"
        self._db.execute_write(sql, (dispersy_id, global_time, channeltorrent_id, peer_id, type, timestamp))
        self.notifier.notify(NTFY_MARKINGS, NTFY_INSERT, channeltorrent_id)

    def on_remove_mark_torrent(self, channel_id, dispersy_id, redo):
        sql = "UPDATE _TorrentMarkings SET deleted_at = ? WHERE dispersy_id = ?"

        if redo:
            deleted_at = None
        else:
            deleted_at = long(time())
        self._db.execute_write(sql, (deleted_at, dispersy_id))

    def on_dynamic_settings(self, channel_id):
        self.notifier.notify(NTFY_CHANNELCAST, NTFY_STATE, channel_id)

    def getNrTorrentsDownloaded(self, channel_id):
        sql = "select count(*) from MyPreference, ChannelTorrents where MyPreference.torrent_id = ChannelTorrents.torrent_id and ChannelTorrents.channel_id = ? LIMIT 1"
        return self._db.fetchone(sql, (channel_id,))

    def getChannelNrTorrents(self, limit=None):
        if limit:
            sql = "select count(torrent_id), channel_id from Channels, ChannelTorrents WHERE Channels.id = ChannelTorrents.channel_id AND dispersy_cid <>  -1 GROUP BY channel_id ORDER BY RANDOM() LIMIT ?"
            return self._db.fetchall(sql, (limit,))

        sql = "select count(torrent_id), channel_id from Channels, ChannelTorrents WHERE Channels.id = ChannelTorrents.channel_id AND dispersy_cid <>  -1 GROUP BY channel_id"
        return self._db.fetchall(sql)

    def getChannelNrTorrentsLatestUpdate(self, limit=None):
        if limit:
            sql = "select count(CollectedTorrent.torrent_id), max(ChannelTorrents.time_stamp), channel_id from Channels, ChannelTorrents, CollectedTorrent WHERE ChannelTorrents.torrent_id = CollectedTorrent.torrent_id AND Channels.id = ChannelTorrents.channel_id AND dispersy_cid == -1 GROUP BY channel_id ORDER BY RANDOM() LIMIT ?"
            return self._db.fetchall(sql, (limit,))

        sql = "select count(CollectedTorrent.torrent_id), max(ChannelTorrents.time_stamp), channel_id from Channels, ChannelTorrents, CollectedTorrent WHERE ChannelTorrents.torrent_id = CollectedTorrent.torrent_id AND Channels.id = ChannelTorrents.channel_id AND dispersy_cid == -1 GROUP BY channel_id"
        return self._db.fetchall(sql)

    def getNrChannels(self):
        sql = "select count(DISTINCT id) from Channels LIMIT 1"
        return self._db.fetchone(sql)

    def getPermidForChannel(self, channel_id):
        sql = "SELECT permid FROM Peer, Channels WHERE Channels.peer_id = Peer.peer_id AND Channels.id = ?"
        return self._db.fetchone(sql, (channel_id,))

    def getRecentAndRandomTorrents(self, NUM_OWN_RECENT_TORRENTS=15, NUM_OWN_RANDOM_TORRENTS=10, NUM_OTHERS_RECENT_TORRENTS=15, NUM_OTHERS_RANDOM_TORRENTS=10, NUM_OTHERS_DOWNLOADED=5):
        torrent_dict = {}

        least_recent = -1
        sql = "select dispersy_cid, infohash, time_stamp from ChannelTorrents, Channels, Torrent where ChannelTorrents.torrent_id = Torrent.torrent_id AND Channels.id = ChannelTorrents.channel_id AND ChannelTorrents.channel_id==? and ChannelTorrents.dispersy_id <> -1 order by time_stamp desc limit ?"
        myrecenttorrents = self._db.fetchall(sql, (self._channel_id, NUM_OWN_RECENT_TORRENTS))
        for cid, infohash, timestamp in myrecenttorrents:
            torrent_dict.setdefault(str(cid), set()).add(str2bin(infohash))
            least_recent = timestamp

        if len(myrecenttorrents) == NUM_OWN_RECENT_TORRENTS and least_recent != -1:
            sql = "select dispersy_cid, infohash from ChannelTorrents, Channels, Torrent where ChannelTorrents.torrent_id = Torrent.torrent_id AND Channels.id = ChannelTorrents.channel_id AND ChannelTorrents.channel_id==? and time_stamp<? and ChannelTorrents.dispersy_id <> -1 order by random() limit ?"
            myrandomtorrents = self._db.fetchall(sql, (self._channel_id, least_recent, NUM_OWN_RANDOM_TORRENTS))
            for cid, infohash, _ in myrecenttorrents:
                torrent_dict.setdefault(str(cid), set()).add(str2bin(infohash))

            for cid, infohash in myrandomtorrents:
                torrent_dict.setdefault(str(cid), set()).add(str2bin(infohash))

        nr_records = sum(len(torrents) for torrents in torrent_dict.values())
        additionalSpace = (NUM_OWN_RECENT_TORRENTS + NUM_OWN_RANDOM_TORRENTS) - nr_records

        if additionalSpace > 0:
            NUM_OTHERS_RECENT_TORRENTS += additionalSpace / 2
            NUM_OTHERS_RANDOM_TORRENTS += additionalSpace - (additionalSpace / 2)

            # Niels 6-12-2011: we should substract additionalspace from recent and random, otherwise the totals will not be correct.
            NUM_OWN_RECENT_TORRENTS -= additionalSpace / 2
            NUM_OWN_RANDOM_TORRENTS -= additionalSpace - (additionalSpace / 2)

        least_recent = -1
        sql = "select dispersy_cid, infohash, time_stamp from ChannelTorrents, Channels, Torrent where ChannelTorrents.torrent_id = Torrent.torrent_id AND Channels.id = ChannelTorrents.channel_id AND ChannelTorrents.channel_id in (select channel_id from ChannelVotes where voter_id ISNULL and vote=2) and ChannelTorrents.dispersy_id <> -1 order by time_stamp desc limit ?"
        othersrecenttorrents = self._db.fetchall(sql, (NUM_OTHERS_RECENT_TORRENTS,))
        for cid, infohash, timestamp in othersrecenttorrents:
            torrent_dict.setdefault(str(cid), set()).add(str2bin(infohash))
            least_recent = timestamp

        if othersrecenttorrents and len(othersrecenttorrents) == NUM_OTHERS_RECENT_TORRENTS and least_recent != -1:
            sql = "select dispersy_cid, infohash from ChannelTorrents, Channels, Torrent where ChannelTorrents.torrent_id = Torrent.torrent_id AND Channels.id = ChannelTorrents.channel_id AND ChannelTorrents.channel_id in (select channel_id from ChannelVotes where voter_id ISNULL and vote=2) and time_stamp < ? and ChannelTorrents.dispersy_id <> -1 order by random() limit ?"
            othersrandomtorrents = self._db.fetchall(sql, (least_recent, NUM_OTHERS_RANDOM_TORRENTS))
            for cid, infohash in othersrandomtorrents:
                torrent_dict.setdefault(str(cid), set()).add(str2bin(infohash))

        twomonthsago = long(time() - 5259487)
        nr_records = sum(len(torrents) for torrents in torrent_dict.values())
        additionalSpace = (NUM_OWN_RECENT_TORRENTS + NUM_OWN_RANDOM_TORRENTS + NUM_OTHERS_RECENT_TORRENTS + NUM_OTHERS_RANDOM_TORRENTS) - nr_records
        NUM_OTHERS_DOWNLOADED += additionalSpace

        sql = "select dispersy_cid, infohash from ChannelTorrents, Channels, Torrent where ChannelTorrents.torrent_id = Torrent.torrent_id AND Channels.id = ChannelTorrents.channel_id AND ChannelTorrents.channel_id in (select distinct channel_id from ChannelTorrents where torrent_id in (select torrent_id from MyPreference)) and ChannelTorrents.dispersy_id <> -1 and Channels.modified > ? order by time_stamp desc limit ?"
        interesting_records = self._db.fetchall(sql, (twomonthsago, NUM_OTHERS_DOWNLOADED))
        for cid, infohash in interesting_records:
            torrent_dict.setdefault(str(cid), set()).add(str2bin(infohash))

        return torrent_dict

    def getRandomTorrents(self, channel_id, limit=15):
        sql = "select infohash from ChannelTorrents, Torrent where ChannelTorrents.torrent_id = Torrent.torrent_id AND channel_id = ? ORDER BY RANDOM() LIMIT ?"

        returnar = []
        for infohash, in self._db.fetchall(sql, (channel_id, limit)):
            returnar.append(str2bin(infohash))
        return returnar

    def getTorrentFromChannelId(self, channel_id, infohash, keys):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND channel_id = ? AND infohash = ?"
        result = self._db.fetchone(sql, (channel_id, bin2str(infohash)))

        return self.__fixTorrent(keys, result)

    def getChannelTorrents(self, infohash, keys):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND infohash = ?"
        results = self._db.fetchall(sql, (bin2str(infohash),))

        return self.__fixTorrents(keys, results)

    def getTorrentFromChannelTorrentId(self, channeltorrent_id, keys):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND ChannelTorrents.id = ?"
        result = self._db.fetchone(sql, (channeltorrent_id,))
        if not result:
            self._logger.info("COULD NOT FIND CHANNELTORRENT_ID %s", channeltorrent_id)
        else:
            return self.__fixTorrent(keys, result)

    def getTorrentsFromChannelId(self, channel_id, isDispersy, keys, limit=None):
        if isDispersy:
            sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id"
        else:
            sql = "SELECT " + ", ".join(keys) + " FROM CollectedTorrent as Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id"

        if channel_id:
            sql += " AND channel_id = ?"
        sql += " ORDER BY time_stamp DESC"

        if limit:
            sql += " LIMIT %d" % limit

        if channel_id:
            results = self._db.fetchall(sql, (channel_id,))
        else:
            results = self._db.fetchall(sql)

        if limit is None and channel_id:
            # use this possibility to update nrtorrent in channel

            if 'time_stamp' in keys and len(results) > 0:
                update = "UPDATE _Channels SET nr_torrents = ?, modified = ? WHERE id = ?"
                self._db.execute_write(update, (len(results), results[0][keys.index('time_stamp')], channel_id))
            else:
                # use this possibility to update nrtorrent in channel
                update = "UPDATE _Channels SET nr_torrents = ? WHERE id = ?"
                self._db.execute_write(update, (len(results), channel_id))

        return self.__fixTorrents(keys, results)

    def getRecentReceivedTorrentsFromChannelId(self, channel_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND channel_id = ? ORDER BY inserted DESC"
        if limit:
            sql += " LIMIT %d" % limit
        results = self._db.fetchall(sql, (channel_id,))
        return self.__fixTorrents(keys, results)

    def getRecentModificationsFromChannelId(self, channel_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM ChannelMetaData LEFT JOIN MetaDataTorrent ON ChannelMetaData.id = MetaDataTorrent.metadata_id LEFT JOIN Moderations ON Moderations.cause = ChannelMetaData.dispersy_id WHERE ChannelMetaData.channel_id = ? ORDER BY -Moderations.time_stamp ASC, ChannelMetaData.inserted DESC"
        if limit:
            sql += " LIMIT %d" % limit
        return self._db.fetchall(sql, (channel_id,))

    def getRecentModerationsFromChannel(self, channel_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM Moderations, MetaDataTorrent, ChannelMetaData WHERE Moderations.cause = ChannelMetaData.dispersy_id AND ChannelMetaData.id = MetaDataTorrent.metadata_id AND Moderations.channel_id = ? ORDER BY Moderations.inserted DESC"
        if limit:
            sql += " LIMIT %d" % limit
        return self._db.fetchall(sql, (channel_id,))

    def getRecentMarkingsFromChannel(self, channel_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM TorrentMarkings, ChannelTorrents WHERE TorrentMarkings.channeltorrent_id = ChannelTorrents.id AND ChannelTorrents.channel_id = ? ORDER BY TorrentMarkings.time_stamp DESC"
        if limit:
            sql += " LIMIT %d" % limit
        return self._db.fetchall(sql, (channel_id,))

    def getMostPopularTorrentsFromChannel(self, channel_id, isDispersy, keys, limit=None):
        if isDispersy:
            sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND channel_id = ? GROUP BY Torrent.torrent_id ORDER BY ChannelTorrents.time_stamp DESC"
        else:
            sql = "SELECT " + ", ".join(keys) + " FROM CollectedTorrent as Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND channel_id = ? GROUP BY Torrent.torrent_id ORDER BY ChannelTorrents.time_stamp DESC"

        if limit:
            sql += " LIMIT %d" % limit
        return self._db.fetchall(sql, (channel_id,))

    def getTorrentsFromPlaylist(self, playlist_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents, PlaylistTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND ChannelTorrents.id = PlaylistTorrents.channeltorrent_id AND playlist_id = ? ORDER BY time_stamp DESC"
        if limit:
            sql += " LIMIT %d" % limit
        results = self._db.fetchall(sql, (playlist_id,))
        return self.__fixTorrents(keys, results)

    def getTorrentFromPlaylist(self, playlist_id, infohash, keys):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents, PlaylistTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND ChannelTorrents.id = PlaylistTorrents.channeltorrent_id AND playlist_id = ? AND infohash = ?"
        result = self._db.fetchone(sql, (playlist_id, bin2str(infohash)))

        return self.__fixTorrent(keys, result)

    def getRecentTorrentsFromPlaylist(self, playlist_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents, PlaylistTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND ChannelTorrents.id = PlaylistTorrents.channeltorrent_id AND playlist_id = ? ORDER BY inserted DESC"
        if limit:
            sql += " LIMIT %d" % limit
        results = self._db.fetchall(sql, (playlist_id,))
        return self.__fixTorrents(keys, results)

    def getRecentModificationsFromPlaylist(self, playlist_id, keys, limit=None):
        playlistKeys = keys[:]
        if 'MetaDataTorrent.channeltorrent_id' in playlistKeys:
            playlistKeys[playlistKeys.index('MetaDataTorrent.channeltorrent_id')] = '""'

        sql = "SELECT " + ", ".join(playlistKeys) + " FROM MetaDataPlaylist, ChannelMetaData LEFT JOIN Moderations ON Moderations.cause = ChannelMetaData.dispersy_id WHERE MetaDataPlaylist.metadata_id = ChannelMetaData.id AND playlist_id = ?"
        if limit:
            sql += " LIMIT %d" % limit
        playlist_modifications = self._db.fetchall(sql, (playlist_id,))

        sql = "SELECT " + ", ".join(keys) + " FROM MetaDataTorrent, ChannelMetaData, PlaylistTorrents LEFT JOIN Moderations ON Moderations.cause = ChannelMetaData.dispersy_id WHERE MetaDataTorrent.metadata_id = ChannelMetaData.id AND PlaylistTorrents.channeltorrent_id = MetaDataTorrent.channeltorrent_id AND playlist_id = ?"
        if limit:
            sql += " LIMIT %d" % limit
        torrent_modifications = self._db.fetchall(sql, (playlist_id,))

        # merge two lists
        orderIndex = keys.index('ChannelMetaData.time_stamp')
        revertIndex = keys.index('Moderations.time_stamp')
        data = [(row[revertIndex], row[orderIndex], row) for row in playlist_modifications]
        data += [(row[revertIndex], row[orderIndex], row) for row in torrent_modifications]
        data.sort(reverse=True)

        if limit:
            data = data[:limit]
        data = [item for _, _, item in data]
        return data

    def getRecentModerationsFromPlaylist(self, playlist_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM Moderations, MetaDataTorrent, ChannelMetaData, PlaylistTorrents WHERE Moderations.cause = ChannelMetaData.dispersy_id AND ChannelMetaData.id = MetaDataTorrent.metadata_id AND MetaDataTorrent.channeltorrent_id = PlaylistTorrents.channeltorrent_id AND PlaylistTorrents.playlist_id = ? ORDER BY Moderations.inserted DESC"
        if limit:
            sql += " LIMIT %d" % limit
        return self._db.fetchall(sql, (playlist_id,))

    def getRecentMarkingsFromPlaylist(self, playlist_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM TorrentMarkings, PlaylistTorrents, ChannelTorrents WHERE TorrentMarkings.channeltorrent_id = PlaylistTorrents.channeltorrent_id AND ChannelTorrents.id = PlaylistTorrents.channeltorrent_id AND PlaylistTorrents.playlist_id = ? AND ChannelTorrents.dispersy_id <> -1 ORDER BY TorrentMarkings.time_stamp DESC"
        if limit:
            sql += " LIMIT %d" % limit
        return self._db.fetchall(sql, (playlist_id,))

    def getTorrentsNotInPlaylist(self, channel_id, keys):
        sql = "SELECT " + ", ".join(keys) + " FROM Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND channel_id = ? And ChannelTorrents.id NOT IN (Select channeltorrent_id From PlaylistTorrents) ORDER BY time_stamp DESC"
        results = self._db.fetchall(sql, (channel_id,))
        return self.__fixTorrents(keys, results)

    def getPlaylistForTorrent(self, channeltorrent_id, keys):
        sql = "SELECT " + ", ".join(keys) + ", count(DISTINCT channeltorrent_id) FROM Playlists, PlaylistTorrents WHERE Playlists.id = PlaylistTorrents.playlist_id AND channeltorrent_id = ?"
        result = self._db.fetchone(sql, (channeltorrent_id,))
        # Niels: 29-02-2012 due to the count this always returns one row, check count to return None if playlist was actually not found.
        if result[-1]:
            return result

    def getPlaylistsForTorrents(self, torrent_ids, keys):
        torrent_ids = " ,".join(map(str, torrent_ids))

        sql = "SELECT channeltorrent_id, " + ", ".join(keys) + ", count(DISTINCT channeltorrent_id) FROM Playlists, PlaylistTorrents WHERE Playlists.id = PlaylistTorrents.playlist_id AND channeltorrent_id IN (" + torrent_ids + ") GROUP BY Playlists.id"
        return self._db.fetchall(sql)

    def __fixTorrent(self, keys, torrent):
        if len(keys) == 1:
            if keys[0] == 'infohash':
                return str2bin(torrent)
            return torrent

        def fix_value(key, torrent):
            if key in keys:
                key_index = keys.index(key)
                if torrent[key_index]:
                    torrent[key_index] = str2bin(torrent[key_index])
        if torrent:
            torrent = list(torrent)
            fix_value('infohash', torrent)
            fix_value('swift_hash', torrent)
            fix_value('swift_torrent_hash', torrent)
        return torrent

    def __fixTorrents(self, keys, results):
        def fix_value(key):
            if key in keys:
                key_index = keys.index(key)
                for i in range(len(results)):
                    result = list(results[i])
                    if result[key_index]:
                        result[key_index] = str2bin(result[key_index])
                        results[i] = result
        fix_value('infohash')
        fix_value('swift_hash')
        fix_value('swift_torrent_hash')
        return results

    def getPlaylistsFromChannelId(self, channel_id, keys):
        sql = "SELECT " + ", ".join(keys) + ", count(DISTINCT ChannelTorrents.id) FROM Playlists LEFT JOIN PlaylistTorrents ON Playlists.id = PlaylistTorrents.playlist_id LEFT JOIN ChannelTorrents ON PlaylistTorrents.channeltorrent_id = ChannelTorrents.id WHERE Playlists.channel_id = ? GROUP BY Playlists.id ORDER BY Playlists.name DESC"
        return self._db.fetchall(sql, (channel_id,))

    def getPlaylist(self, playlist_id, keys):
        sql = "SELECT " + ", ".join(keys) + ", count(DISTINCT ChannelTorrents.id) FROM Playlists LEFT JOIN PlaylistTorrents ON Playlists.id = PlaylistTorrents.playlist_id LEFT JOIN ChannelTorrents ON PlaylistTorrents.channeltorrent_id = ChannelTorrents.id WHERE Playlists.id = ? GROUP BY Playlists.id"
        return self._db.fetchone(sql, (playlist_id,))

    def getCommentsFromChannelId(self, channel_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM Comments LEFT JOIN Peer ON Comments.peer_id = Peer.peer_id LEFT JOIN CommentPlaylist ON Comments.id = CommentPlaylist.comment_id LEFT JOIN CommentTorrent ON Comments.id = CommentTorrent.comment_id WHERE channel_id = ? ORDER BY time_stamp DESC"
        if limit:
            sql += " LIMIT %d" % limit
        return self._db.fetchall(sql, (channel_id,))

    def getCommentsFromPlayListId(self, playlist_id, keys, limit=None):
        playlistKeys = keys[:]
        if 'CommentTorrent.channeltorrent_id' in playlistKeys:
            playlistKeys[playlistKeys.index('CommentTorrent.channeltorrent_id')] = '""'

        sql = "SELECT " + ", ".join(playlistKeys) + " FROM Comments LEFT JOIN Peer ON Comments.peer_id = Peer.peer_id LEFT JOIN CommentPlaylist ON Comments.id = CommentPlaylist.comment_id WHERE playlist_id = ?"
        if limit:
            sql += " LIMIT %d" % limit

        playlist_comments = self._db.fetchall(sql, (playlist_id,))

        sql = "SELECT " + ", ".join(keys) + " FROM Comments, CommentTorrent, PlaylistTorrents LEFT JOIN Peer ON Comments.peer_id = Peer.peer_id WHERE Comments.id = CommentTorrent.comment_id AND PlaylistTorrents.channeltorrent_id = CommentTorrent.channeltorrent_id AND playlist_id = ?"
        if limit:
            sql += " LIMIT %d" % limit

        torrent_comments = self._db.fetchall(sql, (playlist_id,))

        # merge two lists
        orderIndex = keys.index('time_stamp')
        data = [(row[orderIndex], row) for row in playlist_comments]
        data += [(row[orderIndex], row) for row in torrent_comments]
        data.sort(reverse=True)

        if limit:
            data = data[:limit]
        data = [item for _, item in data]
        return data

    def getCommentsFromChannelTorrentId(self, channeltorrent_id, keys, limit=None):
        sql = "SELECT " + ", ".join(keys) + " FROM Comments, CommentTorrent LEFT JOIN Peer ON Comments.peer_id = Peer.peer_id WHERE Comments.id = CommentTorrent.comment_id AND channeltorrent_id = ? ORDER BY time_stamp DESC"
        if limit:
            sql += " LIMIT %d" % limit

        return self._db.fetchall(sql, (channeltorrent_id,))

    def searchChannelsTorrent(self, keywords, limitChannels=None, limitTorrents=None, dispersyOnly=False):
        # search channels based on keywords
        keywords = split_into_keywords(keywords)
        keywords = [keyword for keyword in keywords if len(keyword) > 1]

        if len(keywords) > 0:
            sql = "SELECT distinct id, dispersy_cid, name FROM Channels WHERE"
            for keyword in keywords:
                sql += " name like '%" + keyword + "%' and"

            if dispersyOnly:
                sql += " dispersy_cid != '-1'"
            else:
                sql = sql[:-3]

            if limitChannels:
                sql += " LIMIT %d" % limitChannels

            channels = self._db.fetchall(sql)
            select_torrents = "SELECT infohash, ChannelTorrents.name, Torrent.name, time_stamp from Torrent, ChannelTorrents WHERE Torrent.torrent_id = ChannelTorrents.torrent_id AND channel_id = ? ORDER BY num_seeders DESC LIMIT ?"

            limitTorrents = limitTorrents or 20

            results = []
            for channel_id, dispersy_cid, name in channels:
                dispersy_cid = str(dispersy_cid)
                torrents = self._db.fetchall(select_torrents, (channel_id, limitTorrents))
                for infohash, ChTname, CoTname, time_stamp in torrents:
                    infohash = str2bin(infohash)
                    results.append((channel_id, dispersy_cid, name, infohash, ChTname or CoTname, time_stamp))
            return results
        return []

    def searchChannels(self, keywords):
        sql = "SELECT id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels WHERE"
        for keyword in keywords:
            sql += " name like '%" + keyword + "%' and"
        sql = sql[:-3]
        return self._getChannels(sql)

    def getChannel(self, channel_id):
        sql = "Select id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels WHERE id = ?"
        channels = self._getChannels(sql, (channel_id,))
        if len(channels) > 0:
            return channels[0]

    def getChannelByCID(self, channel_cid):
        sql = "Select id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels WHERE dispersy_cid = ?"
        channels = self._getChannels(sql, (buffer(channel_cid),))
        if len(channels) > 0:
            return channels[0]

    def getChannelFromPermid(self, channel_permid):
        sql = "Select C.id, C.name, C.description, C.dispersy_cid, C.modified, C.nr_torrents, C.nr_favorite, C.nr_spam FROM Channels as C, Peer WHERE C.peer_id = Peer.peer_id AND Peer.permid = ?"
        channels = self._getChannels(sql, (channel_permid,))
        if len(channels) > 0:
            return channels[0]

    def getChannels(self, channel_ids):
        channel_ids = "','".join(map(str, channel_ids))
        sql = "Select id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels WHERE id IN ('" + channel_ids + "')"
        return self._getChannels(sql)

    def getChannelsByCID(self, channel_cids):
        parameters = '?,' * len(channel_cids)
        parameters = parameters[:-1]

        channel_cids = map(buffer, channel_cids)
        sql = "Select id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels WHERE dispersy_cid IN (" + parameters + ")"
        return self._getChannels(sql, channel_cids)

    def getAllChannels(self):
        """ Returns all the channels """
        sql = "Select id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels"
        return self._getChannels(sql)

    def getNewChannels(self, updated_since=0):
        """ Returns all newest unsubscribed channels, ie the ones with no votes (positive or negative)"""
        sql = "Select id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels WHERE nr_favorite = 0 AND nr_spam = 0 AND modified > ?"
        return self._getChannels(sql, (updated_since,))

    def getLatestUpdated(self, max_nr=20):
        def channel_sort(a, b):
            # first compare local vote, spam -> return -1
            if a[7] == -1:
                return 1
            if b[7] == -1:
                return -1

            # then compare latest update
            if a[8] < b[8]:
                return 1
            if a[8] > b[8]:
                return -1
            # finally compare nr_torrents
            return cmp(a[4], b[4])

        sql = "Select id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels Order By modified DESC Limit ?"
        return self._getChannels(sql, (max_nr,), cmpF=channel_sort)

    def getMostPopularChannels(self, max_nr=20):
        sql = "Select id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels ORDER BY nr_favorite DESC, modified DESC LIMIT ?"
        return self._getChannels(sql, (max_nr,), includeSpam=False)

    def getMySubscribedChannels(self, includeDispsersy=False):
        sql = "SELECT id, name, description, dispersy_cid, modified, nr_torrents, nr_favorite, nr_spam FROM Channels, ChannelVotes WHERE Channels.id = ChannelVotes.channel_id AND voter_id ISNULL AND vote == 2"
        if not includeDispsersy:
            sql += " AND dispersy_cid == -1"

        return self._getChannels(sql)

    def _getChannels(self, sql, args=None, cmpF=None, includeSpam=True):
        """Returns the channels based on the input sql, if the number of positive votes is less than maxvotes and the number of torrent > 0"""
        channels = []
        results = self._db.fetchall(sql, args)

        my_votes = self.votecast_db.getMyVotes()
        for id, name, description, dispersy_cid, modified, nr_torrents, nr_favorites, nr_spam in results:
            my_vote = my_votes.get(id, 0)
            if not includeSpam and my_vote < 0:
                continue
            if name.strip() == '':
                continue

            channels.append((id, str(dispersy_cid), name, description, nr_torrents, nr_favorites, nr_spam, my_vote, modified, id == self._channel_id))

        def channel_sort(a, b):
            # first compare local vote, spam -> return -1
            if a[7] == -1:
                return 1
            if b[7] == -1:
                return -1

            # then compare nr_favorites
            if a[5] < b[5]:
                return 1
            if a[5] > b[5]:
                return -1

            # then compare latest update
            if a[8] < b[8]:
                return 1
            if a[8] > b[8]:
                return -1

            # finally compare nr_torrents
            return cmp(a[4], b[4])

        if cmpF == None:
            cmpF = channel_sort
        channels.sort(cmpF)
        return channels

    def getMyChannelId(self):
        if self._channel_id:
            return self._channel_id
        return self._db.fetchone('SELECT id FROM Channels WHERE peer_id ISNULL LIMIT 1')

    def getSubscribersCount(self, channel_id):
        """returns the number of subscribers in integer format"""

        nr_favorites, nr_spam = self.votecast_db.getPosNegVotes(channel_id)
        return nr_favorites

    def getTorrentMarkings(self, channeltorrent_id):
        counts = {}
        sql = "SELECT type, peer_id FROM TorrentMarkings WHERE channeltorrent_id = ?"
        for type, peer_id in self._db.fetchall(sql, (channeltorrent_id,)):
            if type not in counts:
                counts[type] = [type, 0, False]
            counts[type][1] += 1
            if not peer_id:
                counts[type][2] = True
        return counts.values()

    def getTorrentModifications(self, channeltorrent_id, keys):
        sql = "SELECT " + ", ".join(keys) + " FROM MetaDataTorrent, ChannelMetaData LEFT JOIN Moderations ON Moderations.cause = ChannelMetaData.dispersy_id WHERE metadata_id = ChannelMetaData.id AND channeltorrent_id = ? ORDER BY -Moderations.time_stamp ASC, prev_global_time DESC"
        return self._db.fetchall(sql, (channeltorrent_id,))

    def getMostPopularChannelFromTorrent(self, infohash):
        """Returns channel id, name, nrfavorites of most popular channel if any"""
        sql = "select Channels.id, Channels.dispersy_cid, Channels.name, Channels.description, Channels.nr_torrents, Channels.nr_favorite, Channels.nr_spam, Channels.modified, ChannelTorrents.id from Channels, ChannelTorrents, Torrent where Channels.id = ChannelTorrents.channel_id AND ChannelTorrents.torrent_id = Torrent.torrent_id AND infohash = ?"
        channels = self._db.fetchall(sql, (bin2str(infohash),))

        if len(channels) > 0:
            channel_ids = set()
            for result in channels:
                channel_ids.add(result[0])

            myVotes = self.votecast_db.getMyVotes()

            best_channel = None
            for id, dispersy_cid, name, description, nr_torrents, nr_favorites, nr_spam, modified, channeltorrent_id in channels:
                channel = id, dispersy_cid, name, description, nr_torrents, nr_favorites, nr_spam, myVotes.get(id, 0), modified, id == self._channel_id, channeltorrent_id

                # allways prefer mychannel
                if channel[-1]:
                    return channel

                if not best_channel or channel[5] > best_channel[5]:
                    best_channel = channel
                elif channel[5] == best_channel[5] and channel[4] > best_channel[4]:
                    best_channel = channel
            return best_channel


class UserEventLogDBHandler(BasicDBHandler):

    """
    The database handler for logging user events.
    """
    # maximum number of events to store
    # when this maximum is reached, approx. 50% of the entries are deleted.
    MAX_EVENTS = 2 * 10000

    def __init__(self):
        if UserEventLogDBHandler._single is not None:
            raise RuntimeError("UserEventLogDBHandler is singleton")
        db = SQLiteCacheDB.getInstance()
        BasicDBHandler.__init__(self, db, 'UserEventLog')

        self.count = -1

    def addEvent(self, message, type=1, timestamp=None):
        """
        Log a user event to the database. Commits automatically.

        @param message A message (string) describing the event.
        @param type Optional type of event (default: 1). There is no
        mechanism to register user event types.
        @param timestamp Optional timestamp of the event. If omitted,
        the current time is used.
        """
        if timestamp is None:
            timestamp = time()
        self._db.insert(self.table_name,
                        timestamp=timestamp, type=type, message=message)

        if self.count == -1:
            self.count = self._db.size(self.table_name)
        else:
            self.count += 1

        if self.count > UserEventLogDBHandler.MAX_EVENTS:
            sql = \
                '''
            DELETE FROM UserEventLog
            WHERE timestamp < (SELECT MIN(timestamp)
                               FROM (SELECT timestamp
                                     FROM UserEventLog
                                     ORDER BY timestamp DESC LIMIT %s))
            ''' % (UserEventLogDBHandler.MAX_EVENTS / 2)
            self._db.execute_write(sql)
            self.count = self._db.size(self.table_name)


class BundlerPreferenceDBHandler(BasicDBHandler):

    """
    The Bundler Preference database handler singleton for
    storing a chosen bundle method for a particular query.
    """

    def __init__(self):
        if BundlerPreferenceDBHandler._single is not None:
            raise RuntimeError("BundlerPreferenceDBHandler is singleton")
        db = SQLiteCacheDB.getInstance()
        BasicDBHandler.__init__(self, db, 'BundlerPreference')

    def storePreference(self, keywords, bundle_mode):
        query = ' '.join(sorted(set(keywords)))
        self._db.execute_write('INSERT OR REPLACE INTO BundlerPreference (query, bundle_mode) VALUES (?,?)',
                               (query, bundle_mode))

    def getPreference(self, keywords):
        # returns None if query not in db
        query = ' '.join(sorted(set(keywords)))
        return self.getOne('bundle_mode', query=query)


def ranksfind(ranks, key):
    if ranks is None:
        return -1
    try:
        return ranks.index(key) + 1
    except:
        return -1
