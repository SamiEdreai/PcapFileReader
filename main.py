import csv
import pandas as pd
from scapy.layers.inet import TCP, UDP
from scapy.utils import PcapReader


def create_csv_file(file_name, headers):
    f = open(file_name, 'w')
    writer = csv.writer(f)
    writer.writerow(headers)
    return f, writer


def write_row(writer, transport_layer, src, srcport, dst, dstport, flag):
    row = [transport_layer, src, srcport, dst, dstport, flag]
    writer.writerow(row)


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def extract_flag(flags):
    if flags & FIN:
        return FIN
    if flags & SYN:
        return SYN
    if flags & RST:
        return RST
    if flags & PSH:
        return PSH
    if flags & ACK:
        return ACK
    if flags & URG:
        return URG
    if flags & ECE:
        return ECE
    if flags & CWR:
        return CWR


def main():
    headers = ['protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'tcp_flag']
    csv_filename = 'csv_file.csv'
    file, writer = create_csv_file(csv_filename, headers)

    for packet in PcapReader(r'./pcap_file.pcap'):
        try:
            if TCP in packet:
                flag = extract_flag(packet.flags)
                tcp_packet = packet[TCP]
                write_row(writer, "TCP", tcp_packet.underlayer.src, tcp_packet.sport, tcp_packet.underlayer.dst,
                          tcp_packet.dport, flag)
            if UDP in packet:
                flag = extract_flag(packet.flags)
                udp_packet = packet[UDP]
                write_row(writer, "UDP", udp_packet.underlayer.src, udp_packet.sport, udp_packet.underlayer.dst,
                          udp_packet.dport, flag)


        except AttributeError as e:
            pass
    file.close()

    df = pd.read_csv(csv_filename)
    print("the number of unique values ip: " + str(len(df.dst_ip.unique())))
    print('the largest port number:', df['src_port'].max())
    print('the smallest port number:', df['src_port'].min())
    print('the number of tcp_flags:', df['tcp_flag'].where(df['tcp_flag'] == 2).count())


if __name__ == "__main__":
    main()