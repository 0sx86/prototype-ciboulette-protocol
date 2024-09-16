from scapy.all import *
from scapy.packet import Packet
from scapy.fields import ByteField, ShortField, StrField

class Ciboulette(Packet):
    name = "Ciboulette"

    fields_desc = [
        ByteField("version", 0x1),
        StrField("identifier", "ciboulette"),
        ByteField("action", 0x1),
        ByteField("lenght", 0x0),
        StrField("command", "")
    ]
        

