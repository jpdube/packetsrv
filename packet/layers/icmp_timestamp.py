from struct import unpack

"""
Timestamp or Timestamp Reply Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |      Code     |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Originate Timestamp                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Receive Timestamp                                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Transmit Timestamp                                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Addresses

      The address of the source in a timestamp message will be the
      destination of the timestamp reply message.  To form a timestamp
      reply message, the source and destination addresses are simply
      reversed, the type code changed to 14, and the checksum
      recomputed.

   IP Fields:

   Type

      13 for timestamp message;

      14 for timestamp reply message.

   Code

      0

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Identifier

      If code = 0, an identifier to aid in matching timestamp and
      replies, may be zero.

   Sequence Number

      If code = 0, a sequence number to aid in matching timestamp and
      replies, may be zero.

   Description

      The data received (a timestamp) in the message is returned in the
      reply together with an additional timestamp.  The timestamp is 32
      bits of milliseconds since midnight UT.  One use of these
      timestamps is described by Mills [5].

      The Originate Timestamp is the time the sender last touched the
      message before sending it, the Receive Timestamp is the time the
      echoer first touched it on receipt, and the Transmit Timestamp is
      the time the echoer last touched the message on sending it.

      If the time is not available in miliseconds or cannot be provided
      with respect to midnight UT then any time can be inserted in a
      timestamp provided the high order bit of the timestamp is also set
      to indicate this non-standard value.

      The identifier and sequence number may be used by the echo sender
      to aid in matching the replies with the requests.  For example,
      the identifier might be used like a port in TCP or UDP to identify
      a session, and the sequence number might be incremented on each
      request sent.  The destination returns these same values in the
      reply.

      Code 0 may be received from a gateway or a host.

"""


class IcmpTimestamp:
    name = 6

    def __init__(self, packet: bytes):
        self.packet = packet

    @property
    def type(self) -> int:
        return unpack("!B", self.packet[0:1])[0]

    @property
    def code(self) -> int:
        return unpack("!B", self.packet[1:2])[0]

    @property
    def checksum(self) -> int:
        return unpack("!H", self.packet[2:4])[0]

    @property
    def identifier(self) -> int:
        return unpack("!H", self.packet[4:6])[0]

    @property
    def sequence_no(self) -> int:
        return unpack("!H", self.packet[6:8])[0]

    @property
    def origin_ts(self) -> bytes:
        return unpack("!I", self.packet[8:12])[0]

    @property
    def received_ts(self) -> bytes:
        return unpack("!I", self.packet[12:16])[0]

    @property
    def xmit_ts(self) -> bytes:
        return unpack("!I", self.packet[16:20])[0]

    def __str__(self):
        return f"ICMP Timestamp -> type: {self.type}, code: {self.code}, checksum: {self.checksum}, identifier: {self.identifier}, sequence: {self.sequence_no}, Origin ts:{self.origin_ts}, Recv ts: {self.received_ts}, Xmit ts: {self.xmit_ts}"
