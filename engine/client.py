from .network.network import *
from .msgpacker import MsgPacker
from .protocol.protocol import *
from .network.netclient import NetClient
from .uuid_manager import *

GAME_VERSION = "0.6.4, 11.4.4"
GAME_NETVERSION = "0.6 626fce9a778df4d4"
GAME_RELEASE_VERSION = "11.4.4"
CLIENT_VERSIONNR = 11044


class Client:
    def __init__(self):
        self.net_client = NetClient()
        self.map_download_chunk: int = 0
        self.state: int = 0
        self.map_details_present: bool = None
        self.map_details_name: str = None
        self.map_details_sha256: bytearray = None
        self.map_details_crc: int = None

    def run(self, addr: NetAddr):
        self.net_client.open()
        self.net_client.connect(addr)

        while True:
            self.pump_network()

    def pump_network(self):
        self.net_client.update()

        if self.net_client.state() == NETSTATE_ONLINE and self.state == 0:
            print("connected, sending info")
            self.state = 1  # loading
            self.send_info()

        packet = NetChunk()
        while self.net_client.recv(packet):
            if packet.client_id == -1:
                self.process_connless_packet(packet)
            else:
                self.process_server_packet(packet)

    def process_server_packet(self, packet: NetChunk):
        unpacker = Unpacker()
        unpacker.reset(packet.data)

        msgid: int = None
        sys: bool = None
        uuid = bytearray()

        # TODO DO UnpackMessageID
        result, pid, sys, uuid, packer = self.unpack_message_id(unpacker)

        if result == UNPACKMESSAGE_ERROR:
            return
        elif result == UNPACKMESSAGE_ANSWER:
            self.send_msg_exy(packer, MsgFlags.VITAL.value, True)

        if sys:
            if (packet.flags & NET_CHUNKFLAG_VITAL) != 0 and msgid == NETMSG_MAP_DETAILS:
                map = unpacker.get_string(unpacker.SANITIZE_CC|unpacker.SKIP_START_WHITESPACES)
                mapsha256: bytearray = unpacker.get_raw(SHA256_DIGEST_LENGTH)
                mapcrc = unpacker.get_int()
                self.map_details_present = True
                self.map_details_name = map
                self.map_details_sha256 = mapsha256
                self.map_details_crc = mapcrc
            elif (packet.flags & NET_CHUNKFLAG_VITAL) != 0 and msgid == NetMsg.MAP_CHANGE.value:
                map_details_were_present = self.map_details_present
                self.map_details_present = False

                map = unpacker.get_string(unpacker.SANITIZE_CC|unpacker.SKIP_START_WHITESPACES)
                mapcrc = unpacker.get_int()
                mapsize = unpacker.get_int()

                if mapsize < 0:
                    print("invalid map size")

                mapsha256 = bytearray()

                if map_details_were_present and self.map_details_name == map and self.map_details_crc == mapcrc:
                    mapsha256 = self.map_details_sha256

                error = self.load_map_search(map, mapsha256, mapcrc)

                if not error:
                    print("Loading done.")
                else:
                    pass
                    # TODO finish this..

    def load_map_search(self, map, sha256, mapcrc):
        # TODO implement
        raise NotImplementedError

    @staticmethod
    def unpack_message_id(unpacker: Unpacker):
        uuid = bytearray()
        msgid = unpacker.get_int()

        pid = msgid >> 1
        sys = msgid & 1 == True

        if pid < 0 or pid >= OFFSET_UUID:
            return UNPACKMESSAGE_ERROR, pid, sys, uuid, None

        if pid != 0:
            return UNPACKMESSAGE_OK, pid, sys, uuid, None

        uuid, pid = uuidManager.unpack_uuid(unpacker)

        if pid == UUID_INVALID or pid == UUID_UNKNOWN:
            return UNPACKMESSAGE_ERROR, pid, sys, uuid, None

        if sys:
            if pid == NETMSG_WHATIS:
                id2, uuid2 = uuidManager.unpack_uuid(unpacker)
                if id2 == UUID_INVALID:
                    return UNPACKMESSAGE_OK, pid, sys, uuid, None
                if id2 == UUID_UNKNOWN:
                    packer = MsgPacker(NETMSG_IDONTKNOW)
                    packer.add_raw(uuid)
                else:
                    packer = MsgPacker(NETMSG_ITIS)
                    packer.add_raw(uuid)
                    packer.add_str(uuidManager.get_name(id2))
                return UNPACKMESSAGE_ANSWER, pid, sys, uuid, packer
        return UNPACKMESSAGE_OK, pid, sys, uuid, None

    def process_connless_packet(self, packet: NetChunk):
        # aparently this is master sv
        raise NotImplementedError
        pass

    def send_info(self):
        msg = MsgPacker(NetMsg.INFO.value)
        msg.add_str(GAME_NETVERSION, 128)
        msg.add_str("", 128)
        self.send_msg_exy(msg, MsgFlags.VITAL.value | MsgFlags.VITAL.value)

    def send_enter_game(self):
        msg = MsgPacker(NetMsg.ENTERGAME.value)
        self.send_msg_exy(msg, MsgFlags.VITAL.value | MsgFlags.FLUSH.value)

    def send_ready(self):
        msg = MsgPacker(NetMsg.READY.value)
        self.send_msg_exy(msg, MsgFlags.VITAL.value | MsgFlags.FLUSH.value)

    def send_map_request(self):
        msg = MsgPacker(NetMsg.REQUEST_MAP_DATA.value)
        msg.add_int(self.map_download_chunk)
        self.send_msg_exy(msg, MsgFlags.VITAL.value | MsgFlags.FLUSH.value)

    def send_msg_exy(self, msg: MsgPacker, flags: int, system: bool = True):
        packet = NetChunk()
        packet.client_id = 0
        packet.data = msg.buffer

        packet.data[0] <<= 1
        if system:
            packet.data[0] |= 1

        if flags & MsgFlags.VITAL.value:
            packet.flags |= NETSENDFLAG_VITAL
        if flags & MsgFlags.FLUSH.value:
            packet.flags |= NETSENDFLAG_FLUSH

        self.net_client.send(packet)
