from Tribler.dispersy.candidate import CANDIDATE_WALK_LIFETIME
MAX_CIRCUITS_TO_CREATE = 1

CIRCUIT_STATE_READY = 'READY'
CIRCUIT_STATE_CREATING = 'CREATING'
CIRCUIT_STATE_EXTENDING = 'EXTENDING'
CIRCUIT_STATE_TO_BE_EXTENDED = 'TO_BE_EXTENDED'
CIRCUIT_STATE_BROKEN = 'BROKEN'

MESSAGE_CREATE = chr(1)
MESSAGE_CREATED = chr(2)
MESSAGE_EXTEND = chr(3)
MESSAGE_EXTENDED = chr(4)
MESSAGE_DATA = chr(5)
MESSAGE_PING = chr(7)
MESSAGE_PONG = chr(8)
MESSAGE_PUNCTURE = chr(9)
MESSAGE_STATS = chr(10)

AES_KEY_SIZE = 16

MESSAGE_STRING_REPRESENTATION = {
    MESSAGE_CREATE: u'create',
    MESSAGE_CREATED: u'created',
    MESSAGE_EXTEND: u'extend',
    MESSAGE_EXTENDED: u'extended',
    MESSAGE_DATA: u'data',
    MESSAGE_PING: u'ping',
    MESSAGE_PONG: u'pong',
    MESSAGE_PUNCTURE: u'puncture',
    MESSAGE_STATS: u'stats'
}

PING_INTERVAL = (CANDIDATE_WALK_LIFETIME - 5.0) / 4

# we use group 14 of the IETF rfc3526 with a 2048 modulus
# http://tools.ietf.org/html/rfc3526
DIFFIE_HELLMAN_GENERATOR = 2
DIFFIE_HELLMAN_MODULUS = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF