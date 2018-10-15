from enum import Enum


class NetMsg(Enum):
    EX = 0

    # the first thing sent by the client
    # contains the version info for the client
    INFO = 1

    # Sent by server
    MAP_CHANGE = 2
    MAP_DATA = 3
    CON_READY = 4
    SNAP = 5
    SNAPEMPTY = 6
    SNAPSINGLE = 7
    SNAPSMALL = 8
    INPUTTIMING = 9
    RCON_AUTH_STATUS = 10
    RCON_LINE = 11

    AUTH_CHALLENGE = 12
    AUTH_RESULT = 13

    # Sent by client
    READY = 14
    ENTERGAME = 15
    INPUT = 16
    RCON_CMD = 17
    RCON_AUTH = 18
    REQUEST_MAP_DATA = 19

    AUTH_START = 20
    AUTH_RESPONSE = 21

    # Sent by both
    PING = 22
    PING_REPLY = 23
    ERROR = 24

    # Sent by server
    RCON_CMD_ADD = 25
    RCON_CMD_REM = 26

    NETMSGS = 27


class MsgFlags(Enum):
    VITAL = 1
    FLUSH = 2
    NORECORD = 4
    RECORD = 8
    NOSEND = 16


SERVER_TICK_SPEED = 50
SERVER_FLAG_PASSWORD = 0x1

MAX_CLIENTS = 64
VANILLA_MAX_CLIENTS = 16

MAX_INPUT_SIZE = 128
MAX_SNAPSHOT_PACKSIZE = 900

MAX_NAME_LENGTH = 16
MAX_CLAN_LENGTH = 12


class Versions(Enum):
    VANILLA = 0
    DDRACE = 1
    DDNET_OLD = 2
    DDNET_WHISPER = 217
    DDNET_GOODHOOK = 221
    DDNET_EXTRATUNES = 302
    DDNET_RCONPROTECT = 408
    DDNET_ANTIPING_PROJECTILE = 604
    DDNET_HOOKDURATION_TUNE = 607
    DDNET_FIREDELAY_TUNE = 701
    DDNET_UPDATER_FIXED = 707
    DDNET_GAMETICK = 10042
