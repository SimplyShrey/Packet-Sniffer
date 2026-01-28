#!/usr/bin/env python3

import ipaddress
import socket
import struct
import sys
import argparse
import time
# from config import get_gemini_client
from config import get_ai_client

# client = get_gemini_client()
client = get_ai_client()
last_ai_call = 0

class Queue:
  def __init__(self):
    self.queue = []
    
  def enqueue(self, element):
    self.queue.append(element)

  def dequeue(self):
    if self.isEmpty():
      return "Queue is empty"
    return self.queue.pop(0)

  def peek(self):
    if self.isEmpty():
      return "Queue is empty"
    return self.queue[0]

  def isEmpty(self):
    return len(self.queue) == 0

  def size(self):
    return len(self.queue)
  
PQueue = Queue()

parser = argparse.ArgumentParser(description="Network packet sniffer")
parser.add_argument('--ip', help="IP address to sniff on", required=True)
parser.add_argument('--proto', help = "Protocol to sniff (IP/TCP)", required=True)
parser.add_argument('--data', help="Display data", action="store_true")
parser.add_argument('--analysis', help="Display's an ai overview of each packet", action="store_true")
opts = parser.parse_args()

class Packet:
    def __init__(self,data):
        self.packet = data
        header = struct.unpack('<BBHHHBBH4s4s',self.packet[0:20])
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.off = header[4]
        self.ttl = header[5]
        self.pro = header[6]
        self.num = header[7]
        self.src = header[8]
        self.dest = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.dest_addr = ipaddress.ip_address(self.dest)

        self.protocol_map = {1: "ICMP", 6: "TCP"}

        self.window_size = None
        if self.pro == 6:
           tcp_header = struct.unpack('!HHIIBBHHH',self.packet[20:40])
           self.window_size = tcp_header[6]

        try:
            self.protocol = self.protocol_map[self.pro]
        except Exception as e:
            print(f'{e} No protocol for {self.pro}')
            self.protocol = str(self.pro)
    
    def guess_os(self):
        if self.ttl<=64:
            if self.window_size == 5840 or self.window_size == 29200:
                return "Linux"
            return "Linux/Android/iOS"
        elif self.ttl<=128:
            if self.window_size == 8192 or self.window_size == 65535:
                return "Windows"
            return "Windows"
        elif self.ttl <= 255:
            return "Solaris/Cisco"
        return "Unknown OS"

    def print_header_short(self):
        os_label = f"({self.guess_os()})" if self.pro == 6 else " "
        print(f'Protocol: {self.protocol} | OS Label: {os_label} | Path: {self.src_addr} -> {self.dest_addr}')
    def print_data(self):
        data = self.packet[20:]
        has_actual_text = any(32 <= b <= 126 for b in data)
    
        if has_actual_text:
            # print('\n' + '-'*10 + "ASCII START" + '-'*10 + '\n')
            print("\n" + "-"*20 + "\n")
            for b in data:
                if 32<=b<=126:
                    print(chr(b), end='')
                else:
                    print('.',end='')
            print("\n" + "-"*20 + "\n")
#---------------------------------------------------------------------------------------------------------  
#For a gemini Model
# def packet_analyzer(payload):
#     global last_ai_call
#     # if not client or (time.time() - last_ai_call < 20):
#     #     return None 
#     #Self notes, chr(b) converts a byte value into its ascii, 32-126 is the printable ascii range for small letters, capital letters and special characters, and if there's anything beyond the range, it may cause the code to fail so its replaced using a .
#     # ascii_packet = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload[:300])
#     ascii_packet = PQueue.dequeue()
#     hex_sample = payload[:100].hex()
#     prompt = (f"Act as a network analyst. Analyze the packet captured."
#     f"RAW HEX: {hex_sample}\n"
#     f"ASCII STRING: {ascii_packet}\n\n"
#     "The prompt is going to be in simple english, perform a basic analysis in not more than 200 characters. Highlight on the command's purpose and risk."
#     )

#     try:
#         last_ai_call = time.time()
#         response = client.models.generate_content(
#             model= "gemini-2.5-flash",
#             contents = prompt
#         )
#         return response.text
#     except Exception as e:
#         return f"AI error: {e}"
#--------------------------------------------------------------------------------------------------------- 
def packet_analyzer(payload_text):
    if not client: return None

    try:
    
        response = client.chat.completions.create(
            model="nvidia/llama-3.1-nemotron-70b-instruct",
            messages=[
                {"role": "system", "content": "You are a network security analyst. Be brief."},
                {"role": "user", "content": f"Analyze this packet: {payload_text}"}
            ],
            max_tokens=50,
            temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"NVIDIA API Error: {e}"

def sniff(host):
    if opts.proto == 'tcp':
        socket_protocol = socket.IPPROTO_TCP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket_protocol)
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print(f"Bound to host: {host}")
    i = 1
    try:
        while True:            
            raw_data = sniffer.recv(65535)
            packet = Packet(raw_data)
            PQueue.enqueue(packet)
            packet.print_header_short()
            payload = raw_data[20:]
            print(f"\nPacket {i}: \n")
            i = i + 1
            if opts.data:
                packet.print_data()
            if opts.analysis:
                result = packet_analyzer(payload)
                if result and i%2!=0:
                    print(f"\nAI analysis: {result}\n")    
    except KeyboardInterrupt:
        print(f"Connection terminated.")
        sys.exit(1)


  
if __name__ == '__main__':
    sniff(opts.ip)
