import argparse
from flows_hadler import listener


def main():
    parser = argparse.ArgumentParser(description='Anomaly detection.')
    parser.add_argument('--input', type=str, help='Target interface or .pcap file for input traffic.', required=True)
    args = parser.parse_args()
    listener(inp=args.input)


if __name__ == '__main__':
    main()
