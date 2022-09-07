import pyshark
import csv
import pandas as pd



def read_pcap_file(file_name):
    return pyshark.FileCapture(file_name)


def create_csv_file(file_name, headers):
    f = open(file_name, 'w')
    writer = csv.writer(f)
    writer.writerow(headers)
    return f, writer


def main():
    pcap_file = read_pcap_file(r'C:\Users\hunte\PycharmProjects\pcapProject\pcap_file.pcap')

    headers = ['protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'tcp_flag']
    csv_filename = 'csv_file'
    file, writer = create_csv_file(csv_filename, headers)
    count = 0

    for packet in pcap_file:

        try:
            row = [packet.transport_layer, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst,
                   packet[packet.transport_layer].dstport, packet.ip.flags]
            writer.writerow(row)
        except AttributeError as e:
            pass
    file.close()

    df = pd.read_csv(csv_filename)
    print('the number of unique values ip:', str(len(df.dst_ip.unique())))
    print('the largest port number:', df['src_port'].max())
    print('the smallest port number:', df['src_port'].min())
    print('the number of tcp_flags:', df['tcp_flag'].where(df['tcp_flag'] == '0x02').count())


if __name__ == "__main__":
    main()