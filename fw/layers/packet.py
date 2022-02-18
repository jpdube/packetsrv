class Packet:
    name = ''
    _fields = []
    _fields_list = {}

    def __init__(self, **kwargs):

        # print('Super init called')

        for name, value in kwargs.items():
            if name in self._fields:
                self._fields_list[name] = value
                setattr(self, f'{name}', value)
            else:
                print(f'Invalid field: {name}')

        self._raw_packet = None
        self.child_layer = None
        self.parent_layer = None

    def add_layer(self, packet):
        if isinstance(packet, Packet):
            self.child_layer = packet
            self.parent_layer = self

    def __add__(self, other_packet):
        print(f'In ADD operation: {self}: {self.name}')
        #  print(f'In ADD operation: src name: {self.layer_name}, other: {other_packet.layer_name}')
        if isinstance(other_packet, Packet):
            #  return self.add_layer(other_packet)
            packet_a = self.copy()
            packet_b = other_packet.copy()
            packet_a.add_layer(packet_b)
            return packet_a
        else:
            return None

    def copy(self):
        new_copy = self.__class__()
        new_copy.child_layer = self.child_layer
        new_copy.parent_layer = self.parent_layer
        new_copy._fields_list = self._fields_list
        new_copy._raw_packet = self._raw_packet
        new_copy.name = self.name

        return new_copy

    def __str__(self):
        return f'Packet, name: {self.name}, child layer: {self.child_layer}, '


if __name__ == '__main__':
    p1 = Packet(layer_name='ethernet')
    p2 = Packet(layer_name='ipv4')
    p3 = p1 + p2

    print(p1)
    print(p2)
    print(f'Packet 3: {p3}')
