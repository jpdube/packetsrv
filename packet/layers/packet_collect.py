
from packet.layers.packet_builder import PacketBuilder


class PacketCollection:
    def __init__(self):
        self.plist = []

    def add(self, pb: PacketBuilder):
        self.plist.append(pb)

    def export(self):
        pass
