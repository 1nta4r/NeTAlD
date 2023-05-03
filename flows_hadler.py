from packet_handler import mac_to_vendor, create_fingerprint, os_predictor
from anomaly_db_worker import create_ald_anomaly_table, add_anomaly_object
from nfstream import NFStreamer, NFPlugin
from scapy.layers.inet import IP
import db_initializer
import ipaddress


MAC_PD_FRAME, CLIENT_FINGERPRINTS, SERVER_FINGERPRINTS, MODEL = db_initializer.initialize()
create_ald_anomaly_table()


def listener(inp: str):
    print("  AAA   LL      DDDDD   ")
    print(" AAAAA  LL      DD  DD  ")
    print("AA   AA LL      DD   DD ")
    print("AAAAAAA LL      DD   DD ")
    print("AA   AA LLLLLLL DDDDDD  ")
    print("======================")
    print("Databases inited.")
    print("Traffic analysis started.")
    print("Anomaly database \"db/ald_anomalies.db\"")
    streams = NFStreamer(source=inp, udps=FlowAnalyzer(), statistical_analysis=True, accounting_mode=3)
    for flow in streams:
        pass
    print("End of handling.")


class FlowAnalyzer(NFPlugin):

    def on_init(self, packet, flow):
        flow.udps.client_fingerprint = ""
        flow.udps.server_fingerprint = ""

        flow.udps.client_os_predicts = ""
        flow.udps.server_os_predicts = ""

        flow.udps.client_device_type = ""
        flow.udps.server_device_type = ""
        if packet.syn and not packet.ack:
            scapy_packet = IP(packet.ip_packet)
            flow.udps.client_fingerprint = create_fingerprint(scapy_packet)
            flow.udps.client_os_predicts, flow.udps.client_device_type, _ = os_predictor(flow.udps.client_fingerprint,
                                                                                         CLIENT_FINGERPRINTS)

    def on_update(self, packet, flow):
        if packet.syn and packet.ack:
            scapy_packet = IP(packet.ip_packet)
            flow.udps.server_fingerprint = create_fingerprint(scapy_packet)
            flow.udps.server_os_predicts, flow.udps.client_device_type, _ = os_predictor(flow.udps.server_fingerprint,
                                                                                         SERVER_FINGERPRINTS)

    def on_expire(self, flow):
        flow_handler(flow)


def flow_handler(flow):
    proba = make_classifirs_list(flow)
    good_rate, bad_rate = MODEL.predict_proba(proba)[0]
    src_mac_label, dst_mac_label, src_vendor, dst_vendor = mac_to_vendor(flow, MAC_PD_FRAME)
    category_name = flow.application_category_name
    application_name = flow.application_name
    app_is_guessed = bool(flow.application_is_guessed)
    flow_location = get_flow_location(flow)
    rules_anomaly_rate = 0
    if category_name == "Unknown":
        rules_anomaly_rate += 5
    if application_name == "Unspecified":
        rules_anomaly_rate += 15
    if app_is_guessed:
        rules_anomaly_rate += 7
    if flow_location == "Internal":
        if src_mac_label == 0 or dst_mac_label == 0:
            rules_anomaly_rate += 20
    else:
        if src_mac_label == 0 and dst_mac_label == 0:
            rules_anomaly_rate += 20
        elif src_mac_label == 0 or dst_mac_label == 0:
            rules_anomaly_rate += 5
    if flow.protocol == 6:
        if flow_location == "Internal":
            if flow.udps.client_os_predicts == "" and flow.udps.server_os_predicts == "":
                rules_anomaly_rate += 20
            elif flow.udps.client_os_predicts == "" or flow.udps.server_os_predicts == "":
                rules_anomaly_rate += 5
        else:
            if flow.udps.client_os_predicts == "" and flow.udps.server_os_predicts == "":
                rules_anomaly_rate += 7
            elif flow.udps.client_os_predicts == "" or flow.udps.server_os_predicts == "":
                rules_anomaly_rate += 3
    rules_anomaly_rate = rules_anomaly_rate / 100
    if bad_rate > 0.95 or (bad_rate > 0.7 and rules_anomaly_rate > 0.21):
        anomaly_object = create_anomaly_db_object(flow, rules_anomaly_rate, bad_rate)
        add_anomaly_object(anomaly_object)


def get_flow_location(flow) -> str:
    source_ip = ipaddress.ip_address(flow.src_ip)
    destination_ip = ipaddress.ip_address(flow.dst_ip)
    if source_ip.is_private and destination_ip.is_private:
        return "Internal"
    return "External"


def make_classifirs_list(flow) -> list:
    result = [[flow.dst2src_min_ps, flow.dst2src_stddev_ps, flow.bidirectional_max_piat_ms,
              flow.bidirectional_min_piat_ms, flow.src2dst_max_ps, flow.dst2src_packets,
              flow.bidirectional_duration_ms]]
    return result


def create_anomaly_db_object(flow, rule_rate, bad_rate) -> tuple:
    return flow.src_ip, flow.src_mac, flow.dst_ip, flow.dst_mac, flow.bidirectional_first_seen_ms, rule_rate, bad_rate



