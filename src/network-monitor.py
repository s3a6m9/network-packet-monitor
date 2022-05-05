"""
This script is for monitoring raw internet packets to determine whether
there are any suspicious connections which may be malicious.
"""
import os
import json
import pyshark

WORKING_PATH = os.path.abspath(os.path.dirname(__file__))


def load_whitelisted_ips(path_to_json: str):
    """
    Returns the json file contents with whitelisted ips
    from previous sessions.
    """
    with open(path_to_json, "r", encoding="utf-8") as json_file:
        return json.load(json_file)


def write_whitelisted_ips(path_to_json: str, whitelisted_ips: list):
    """
    Writes the whitelisted ip list contents with json.dumps to json
    file.
    """
    with open(path_to_json, "w", encoding="utf-8") as write_json_file:
        json.dump(whitelisted_ips, write_json_file, indent=2)


def log_unauthorised_packet(
    path_to_log_file: str, file_write_mode: str, packet: str):
    """
    Checks to see if the log file exists and saves the raw packet
    information into a json file.
    """
    with open(
        path_to_log_file, file_write_mode, encoding="utf-8") as log_file:
        log_file.write(f"{packet}\n\n\n==+ END OF PACKET +==\n\n\n")


def load_unauthorised_packets(path_to_log_file: str):
    """
    Returns the packets saved in the packet log file in a list.
    Packets are split into a list by "{+ END OF PACKET +}"
    """
    with open(path_to_log_file, "r", encoding="utf-8") as log_file:
        return log_file.read().split("==+ END OF PACKET +==")


def live_device_packets(
    local_network_device_ip: str, network_interface: str=None):
    """
    Yields raw packets that the ip specified device produces.

    local_network_ip = <ip.address.of.device>
    network_interface = <network-interface-name>  (e.g. "Wlan0")
    """
    capture = pyshark.LiveCapture(
        interface=network_interface,
        bpf_filter=f"src {local_network_device_ip}")

    for raw_packet in capture.sniff_continuously():
        yield raw_packet


def file_capture_device_packets(
    local_network_device_ip: str, full_output_path: str,
    network_interface=None):
    """
    Captures all live raw packets from a device on the local
    network and outputs to the full output path specified.

    Example:
    local_network_device_ip = "10.23.56.321"
    full_output_path = "/path/to/destination/file_name.cap"
    network_interace = "wlan0"
    """
    capture = pyshark.LiveCapture(
        output_file=full_output_path, interface=network_interface,
        bpf_filter=f"src {local_network_device_ip}")

    for packet in capture.sniff_continuously():
        yield packet


def ask_to_whitelist(destination_ip):
    """
    Prompts user with input asking if the ip should be whitelisted
    and returns a boolean value, True if yes, False if no.
    """
    decision = input(f"Do you want to whitelist '{destination_ip}' || [y/n]: ")
    if decision.lower() == "y":
        return True
    else:
        return False


def monitor_device(
    device_ip: str, network_interface: str,ip_whitelist_filepath: str,
    unauthorised_packet_log_filepath: str, ask_ip_whitelisting=False):
    """
    Monitors live packets and checks if the ips are whitelisted.
    Whitelisted ips are retrieved from the whitelist json file if the
    file exists.

    Unauthorised ips have the packets logged into the unauthorised
    packet log filepath.

    If ask_ip_whitelisting is set to True, the user is prompted whether
    or not to whitelist an ip.
    """
    iwf = ip_whitelist_filepath
    uplf = unauthorised_packet_log_filepath

    whitelisted_ips = []
    if os.path.isfile(iwf):
        whitelisted_ips = load_whitelisted_ips(iwf)
        print(whitelisted_ips)

    if os.path.isfile(uplf):
        uplf_write_mode = "a"
    else:
        uplf_write_mode = "w"

    blacklisted_ips = []  # Renews every session
    for packet in live_device_packets(device_ip, network_interface):
        if hasattr(packet, 'ip'):
            d_ip = packet.ip.dst

            if not d_ip in whitelisted_ips and not d_ip in blacklisted_ips:
                if ask_ip_whitelisting:
                    if ask_to_whitelist(d_ip):
                        whitelisted_ips.append(d_ip)
                        write_whitelisted_ips(iwf, whitelisted_ips)
                        continue
                    else:
                        blacklisted_ips.append(d_ip)

            if d_ip in whitelisted_ips:
                continue

            log_unauthorised_packet(
                os.path.join(
                    uplf,
                    d_ip.replace(".", "-") + ".txt"),
                file_write_mode=uplf_write_mode, packet=packet)

            uplf_write_mode = "a"


def main():
    """
    Main function that runs if file is executed directly.
    """
    whitelist_ip_log_file = os.path.join(
        WORKING_PATH, "whitelisted_ips.json")

    unauthorised_packet_log_file = os.path.join(
        WORKING_PATH, "unauthorised-packets")

    monitor_device(
        "192.168.0.50",
        "wlp3s0",
        whitelist_ip_log_file,
        unauthorised_packet_log_file,
        ask_ip_whitelisting=True)


if __name__ == '__main__':
    main()
