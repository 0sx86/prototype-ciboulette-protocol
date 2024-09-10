from scapy.all import *
from scapy.packet import Packet
from scapy.fields import ByteField, ShortField, StrField

class Ciboulette(Packet):
    name = "Ciboulette"

    fields_desc = [
        StrField("identifier", "ciboulette"),
        ByteField("action", 0x01),
        ByteField("lenght", 0x00),
        StrField("command", "")
    ]
        

