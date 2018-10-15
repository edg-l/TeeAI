from .packer import Packer
from .uuid_manager import OFFSET_UUID, uuidManager


class MsgPacker(Packer):
    def __init__(self, _type: int):
        super().__init__()
        self.reset()
        if _type < OFFSET_UUID:
            self.add_int(_type)
        else:
            # NETMSG_EX, NETMSGTYPE_EX
            self.add_int(0)
            uuidManager.pack_uuid(_type, self)
