import xml.etree.ElementTree as ET
import pandas as pd
import joblib

SIG_OPTIONS = {"M": "1", "N": "2", "S": "3", "T": "4", "W": "5", "E": "6", "K": "7"}


def initialize():
    """Load needed databases to memory"""
    fp_head = ["window", "ttl", "df", "ip_tcp_len", "mss", "ws", "tcp_options", "oddities", "weight", "predict",
               "device_type"]
    try:
        fingerprints_tree = ET.parse('db//tcp.xml')
        root = fingerprints_tree.getroot()
    except():
        print("Bad fingerprints db format.")
        return -1
    all_signatures = root[0]
    syn_ack = []
    syn = []
    for fingerprints_list in all_signatures:
        predict, device_type = satori_label_parser(fingerprints_list.attrib)
        for tests in fingerprints_list:
            for test in tests:
                list_of_fields = test.attrib["tcpsig"].split(":")
                df_row = list_of_fields[:4]
                mss, ws, short_options = "", "", ""
                if list_of_fields[4] != "":
                    mss, ws, short_options = satori_options_parser(list_of_fields[4])
                df_row.append(mss)
                df_row.append(ws)
                df_row.append(short_options)
                df_row.append(list_of_fields[5])
                df_row.append(test.attrib["weight"])
                df_row.append(predict)
                df_row.append(device_type)
                if test.attrib["tcpflag"] == "SA":
                    syn_ack.append(df_row)
                elif test.attrib["tcpflag"] == "S":
                    syn.append(df_row)
    try:
        mac_pd_frame = pd.read_csv("db//macaddress_db.csv")
        client_fingerprints = pd.DataFrame(syn, columns=fp_head)
        server_fingerprints = pd.DataFrame(syn_ack, columns=fp_head)
        model = joblib.load("db//model.pkl")
    except():
        print("Bad db format.")
        return -1
    return mac_pd_frame, client_fingerprints, server_fingerprints, model


def satori_options_parser(options: str):
    """Convert list of options in satori format to short format"""
    mss = "-1"
    ws = "0"
    short_options = ""
    options_list = options.split(",")
    for option in options_list:
        if "M" in option:
            short_options += SIG_OPTIONS["M"]
            mss = option.split("M")[1]
        elif "W" in option:
            short_options += SIG_OPTIONS["W"]
            ws = option.split("W")[1]
        elif "T" in option:
            short_options += "4"
        else:
            short_options += SIG_OPTIONS[option]
    return mss, ws, short_options


def satori_label_parser(satori_label: str):
    device_type = satori_label["device_type"]
    predict = ""
    if satori_label["os_name"] != "":
        predict = satori_label["os_name"]
    elif satori_label["name"] != "":
        predict = satori_label["name"]
    return predict, device_type

