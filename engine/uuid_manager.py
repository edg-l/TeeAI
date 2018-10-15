import os
from hashlib import md5
from .unpacker import Unpacker
from .packer import Packer
from typing import List

UUID_MAXSTRSIZE = 37
UUID_INVALID = -2
UUID_UNKNOWN = -1
OFFSET_UUID = 1 << 16

UUID_SIZE = 16

TEEWORLDS_NAMESPACE = bytearray()
TEEWORLDS_NAMESPACE.extend([0xe0, 0x5d, 0xda, 0xaa, 0xc4, 0xe6, 0x4c, 0xfb,
                            0xb6, 0x42, 0x5d, 0x48, 0xe8, 0x0c, 0x00, 0x29])


class Name:
    def __init__(self):
        self.uuid = bytearray(UUID_SIZE)
        self.name: str = ""


class UuidManager:
    def __init__(self):
        self.names: List[Name] = []

    def register_name(self, _id: int, name: str):
        assert self.get_index(_id) == len(self)

        _name = Name()
        _name.name = name
        _name.uuid = self.calculate_uuid(name)

        assert self.lookup_uuid(_name.uuid) == -1

        self.names.append(_name)

    def pack_uuid(self, _id: int, packer: Packer):
        uuid = self.get_uuid(_id)
        packer.add_raw(uuid)

    def unpack_uuid(self, unpacker: Unpacker):
        uuid = unpacker.get_raw(UUID_SIZE)

        if not uuid:
            return None, UUID_INVALID
        return uuid, self.lookup_uuid(uuid)

    def get_uuid(self, _id: int):
        return self.names[UuidManager.get_index(_id)].uuid

    def get_name(self, _id: int):
        return self.names[UuidManager.get_index(_id)].name

    def lookup_uuid(self, uuid: bytearray):
        for i, x in enumerate(self.names):
            if uuid == x.uuid:
                return self.get_id(i)
        return UUID_UNKNOWN

    @staticmethod
    def calculate_uuid(name: str):
        # TODO: DO THIS
        _hash = md5(TEEWORLDS_NAMESPACE)
        _hash.update(name)

        result = _hash.digest()

        result[6] &= 0x0f
        result[6] |= 0x30
        result[8] &= 0x3f
        result[8] |= 0x80
        return result

    @staticmethod
    def random_uuid():
        result = bytearray(os.urandom(16))
        result[6] &= 0x0f
        result[6] |= 0x40
        result[8] &= 0x3f
        result[8] |= 0x80
        return result

    def __len__(self):
        return len(self.names)

    @staticmethod
    def get_id(index: int):
        return index + OFFSET_UUID

    @staticmethod
    def get_index(_id: int):
        return _id - OFFSET_UUID


NETMSG_EX_INVALID = UUID_INVALID
NETMSG_EX_UNKNOWN = UUID_UNKNOWN
OFFSET_NETMSG_UUID = OFFSET_UUID
__NETMSG_UUID_HELPER = OFFSET_NETMSG_UUID - 1
NETMSG_WHATIS = __NETMSG_UUID_HELPER + 1
NETMSG_ITIS = NETMSG_WHATIS + 1
NETMSG_IDONTKNOW = NETMSG_ITIS + 1
NETMSG_RCONTYPE = NETMSG_IDONTKNOW + 1
NETMSG_MAP_DETAILS = NETMSG_RCONTYPE + 1
OFFSET_TEEHISTORIAN_UUID = NETMSG_MAP_DETAILS + 1
UNPACKMESSAGE_ERROR = 0
UNPACKMESSAGE_OK = 1
UNPACKMESSAGE_ANSWER = 2

uuidManager = UuidManager()
