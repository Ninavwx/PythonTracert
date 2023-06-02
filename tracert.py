"""
Program that traces the route of a packet till its destination ip
Copy of the tracert tool
"""

from scapy.all import *
import datetime

from scapy.layers.dns import DNSRR

IP_ERROR = -1
MAX_HOPS = 30

# constants for the get_ip_from_domain_name function
IP_DNS_REQUEST = '8.8.8.8'
DESTINATION_DNS_PORT = 53
RETURN_IP_INDEX = DNSRR
FOUND_IP_CODE = 'ok'


def main():

    # input the domain name and get the ip from it
    domain_name = input_domain_name()
    # Get the ip of the domain, so that we can check if it is right
    domain_ip = get_ip_from_domain_name(domain_name)

    # if the ip is valid
    if domain_ip != IP_ERROR:

        # call the tracert function to trace the route till the desired ip
        print("Tracing route to {} [{}] over a maximum of {} hops".format(domain_name, domain_ip, MAX_HOPS))

        tracert(domain_ip, 1)

        print("\nTrace complete.")

    else:
        print("Could not find ip from the given host {}".format(domain_name))


def send_icmp_packet(ip_dest, packet_ttl):
    """
    Function to send an icmp packet to a given ip with the given ttl
    :param ip_dest: the ip to send the packet to
    :return: the ip that sent the answer
    """
    sent_successfully = True

    try:
        # generate a request ans send it
        ping_request = Ether() / IP(ttl=packet_ttl, dst=ip_dest) / ICMP()
        ping_ans = srp1(ping_request, verbose=0, timeout=4)

    except ScapyNoDstMacException:
        sent_successfully = False
    except Scapy_Exception:
        sent_successfully = False
    except OSError:
        sent_successfully = False

    ans_ip = 0

    if sent_successfully:

        if ping_ans:  # if the time is out, ping_ans will be None

            # get the answer ip
            ans_ip = ping_ans[IP].src

            # print the results
            print("{}: {}".format(packet_ttl, ans_ip))

        else:
            print("{}: Request timed out".format(packet_ttl))

    else:
        print("{}: Error".format(packet_ttl))

    return ans_ip


def tracert(final_ip, curr_ttl):
    """
    Function to show the route a packet does until it reaches its destination using the tracert logic
    * it is a recursive function that if it did not get to the max hops nor found the final_ip it will call itself again with one more hop
    :param final_ip: the ip ro trace the route to
    :param curr_ttl: the current time to live for the packer
    :return: None
    """
    if curr_ttl < MAX_HOPS:  # if didnt get to the final hop

        curr_ip = send_icmp_packet(final_ip, curr_ttl)

        if curr_ip != final_ip:
            tracert(final_ip, curr_ttl + 1)


def get_ip_from_domain_name(domain_name):
    """
    Function to get the ip from a given domain name
    The function gets the ip through a dns request
    if cannot find the ip returns an error code
    :param domain_name: the domain to ge tthe ip from :type: str
    :return: the ip
    """
    # create a dns request with the domain name
    dns_req = IP(dst=IP_DNS_REQUEST) / UDP(dport=DESTINATION_DNS_PORT) / DNS(rd=1, qd=DNSQR(qname=domain_name))

    # send the request
    dns_answer = sr1(dns_req, verbose=0)

    # set the ip as the error, if the ip is found it will be changed
    ip_from_domain = IP_ERROR

    # get the request code, check if the operation succeeded (has the ip) and print accordingly
    if RETURN_IP_INDEX in dns_answer:
        ip_from_domain = dns_answer[RETURN_IP_INDEX].rdata

    return ip_from_domain


def input_domain_name():
    """
    Function to ask for and input the domain name
    :return: the inputted domain :type: str
    """
    # input the domain name from user
    domain_name = input("Insert domain name: ")
    return domain_name


if __name__ == '__main__':
    main()
