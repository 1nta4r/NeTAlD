from scapy.layers.inet import TCP, ICMP


OPTIONS = {"mss": "1", "nop": "2", "sackok": "3", "timestamp": "4", "wscale": "5", "eol": "6"}


def mac_to_vendor(flow, mac_pd_frame):
    """Determining the vendor by MAC address"""
    mac_templates = mac_pd_frame["oui"]
    src_mac = flow.src_mac.upper()
    dst_mac = flow.dst_mac.upper()
    src_num = 0
    dst_num = 0
    src_vendor = ""
    dst_vendor = ""
    for num in range(len(mac_templates)):
        if src_mac.startswith(mac_templates[num]):
            src_num = num + 1
            src_vendor = mac_pd_frame["companyName"][num]
        if dst_mac.startswith(mac_templates[num]):
            dst_num = num + 1
            dst_vendor = mac_pd_frame["companyName"][num]
        if src_num != 0 and dst_num != 0:
            return src_num, dst_num, src_vendor, dst_vendor
    return src_num, dst_num, src_vendor, dst_vendor


def options_parser(options_list):
    """Parser for packet[TCP].options list."""
    wscale_value = "0"
    mss_value = "-1"
    ts_value = "-1"
    options = ""
    for param in options_list:
        options += (OPTIONS[param[0].lower()])
        if param[0].lower() == "mss":
            mss_value = str(param[1])
        elif param[0].lower() == "wscale":
            wscale_value = str(param[1])
        elif param[0].lower() == "timestamp":
            if param[1][1] > 0:
                ts_value = "1"
            else:
                ts_value = "0"
    return options, mss_value, wscale_value, ts_value


def create_fingerprint(scapy_packet) -> str:
    """Scapy packet to fingerprint"""
    lvl_3_proto = "TCP"
    if TCP not in scapy_packet:
        if ICMP in scapy_packet:
            print("Not clear TCP")
            lvl_3_proto = "TCP in ICMP"
        else:
            return ""

    fingerprint = "{0}:".format(str(scapy_packet[lvl_3_proto].window))
    """ttl to init ttl"""
    ttl = scapy_packet["IP"].ttl
    if ttl < 64:
        ttl = "64"
    elif 64 < ttl < 128:
        ttl = "128"
    elif 128 < ttl < 255:
        ttl = "255"
    else:
        ttl = str(scapy_packet["IP"].ttl)
    fingerprint += "{0}:".format(ttl)

    df = "0"
    if "DF" in scapy_packet["IP"].flags:
        df = "1"
    fingerprint += "{0}:".format(df)
    fingerprint += "{0}:".format(str(scapy_packet["IP"].len))

    options, mss_value, wscale_value, ts_value = options_parser(scapy_packet[lvl_3_proto].options)
    fingerprint += "{0}:".format(mss_value)
    fingerprint += "{0}:".format(wscale_value)
    fingerprint += "{0}:".format(options)

    ip = scapy_packet["IP"]
    tcp = scapy_packet[lvl_3_proto]
    ip_hlen = scapy_packet["IP"].ihl
    ip_ver = scapy_packet["IP"].version
    tcp_hlen = scapy_packet[lvl_3_proto].dataofs
    tcp_flags = scapy_packet[lvl_3_proto].flags
    tcp_options = scapy_packet[lvl_3_proto].options
    er = -1
    if ts_value != "-1":
        for option in tcp_options:
            if option[0].lower() == "timestamp":
                er = option[1][1]
                break
    odd = create_oddities(ip, ip_hlen, ip_ver, tcp_hlen, tcp_flags, tcp, tcp_options, er)
    fingerprint += "{0}".format(odd)
    return fingerprint


def create_oddities(ip, ip_hlen, ip_ver, tcp_hlen, tcp_flags, tcp, tcp_options, options_er):
    """Fingerprint oddities creation"""
    lngt = 0
    odd = ""
    if tcp_options[-1][0].lower == "experiment":
        odd += "P"
    if ip.id == 0:
        odd += "Z"
    if (ip_hlen * 4) > 20:
        odd += "I"
    if ip_ver == 4:
        lngt = ip.len - (tcp_hlen * 4) - (ip_hlen * 4)
    if lngt > 0:
        odd += "D"
    if "U" in tcp_flags:
        odd += "U"
    if (tcp_flags == "S" or tcp_flags == "SA") and tcp.ack != 0:
        odd += "A"
    if tcp_flags == "S" and options_er != 0 and options_er != -1:
        odd += "T"
    if tcp_flags == "SA" and options_er != -1:
        odd += "T"
    if tcp_flags != "SA" and tcp_flags != "S":
        odd += "F"
    if odd == "":
        odd = "."
    return odd


def os_predictor(fingerprint, fingerprints_frame):
    predicts = []
    fields_list = fingerprint.split(":")
    del fields_list[1]
    for index, row in fingerprints_frame.iterrows():
        signature = dict(row)
        weight = signature.pop("weight")
        predict = signature.pop("predict")
        device_type = signature.pop("device_type")
        signature_list = list(signature.values())
        del signature_list[1]
        if fields_list == signature_list:
            if not predicts:
                predicts.append((predict, device_type, weight))
            else:
                for index, pred_obj in enumerate(predicts):
                    if weight < pred_obj[2]:
                        break
                    elif weight == pred_obj[2] and (predict, device_type, weight) != pred_obj:
                        predicts.append((predict, device_type, weight))
                    else:
                        predicts = [(predict, device_type, weight)]
    if predicts:
        return predicts[0]
    return "", "", ""

