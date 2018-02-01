#!/usr/bin/python3
"""
@file ztcc.py
@author Josh M. <cyrex562@gmail.com>
@brief Zero Tier Controller Command Line Tool (ZTCC)
"""

# TODO: add command line for --verbose to show debug messages
# TODO: test external routing
# TODO: format output
# TODO: test environment variables
# TODO: catch exceptions thrown by get and post request code
# -- comma-separated data
# -- json
# -- raw

# IMPORTS
import argparse
import json

import logging

import os
import re

import sys
import urllib.request
import urllib.parse

import requests

# DEFINES

LOGGING_FMT_STR = '%(asctime)s: %(levelname)s: %(funcName)s: %(message)s'
LOGGING_DATEFMT_STR = '%Y-%b-%d %H:%M:%S'
logging.basicConfig(format=LOGGING_FMT_STR,
                    datefmt=LOGGING_DATEFMT_STR,
                    level=logging.DEBUG)


# FUNCTIONS
def process_command_line(args:list)->argparse.Namespace:
    """
    Process the command line
    :return:
    """
    parser = argparse.ArgumentParser(description="CLI for zero tier controller")
    parser.add_argument('command',
                        help="command",
                        choices=["network", "member"])
    parser.add_argument('action',
                        help="CRUD action",
                        choices=["list", "get", "create", "update", "delete"])
    parser.add_argument('--auth_token',
                        help='auth token')
    parser.add_argument('--network',
                        help='network ID')
    parser.add_argument('--member',
                        help='member ID')
    parser.add_argument('--controller',
                        help="controller address")
    parser.add_argument('--port',
                        help="listening port for zt controller",
                        type=int,
                        default=9993)
    parser.add_argument('--host',
                        help="host for zt controller",
                        default="localhost")
    parser.add_argument("--name",
                        help="network name")
    parser.add_argument("--private",
                        dest="private",
                        action="store_true",
                        help="network is private")
    parser.add_argument("--not_private",
                        dest="private",
                        action="store_false",
                        help="network is public")
    parser.add_argument("--enable_broadcast",
                        dest="broadcast",
                        action="store_true",
                        help="enable ethernet broadcast")
    parser.add_argument("--disable_broadcast",
                        dest="broadcast",
                        action="store_false",
                        help="disable ethernet broadcast")
    # parser.add_argument("--enable_passive_bridging",
    #                     dest="passive_bridging",
    #                     action="store_true",
    #                     help="enable passive bridging")
    # parser.add_argument("--disable_passive_bridging",
    #                     dest="passive_bridging",
    #                     action="store_false",
    #                     help="disable passive bridging")
    parser.add_argument("--enable_v4_assign",
                        dest="v4_assign",
                        action="store_true",
                        help="assign ipv4 addresses to members")
    parser.add_argument("--disable_v4_assign",
                        dest="v4_assign",
                        action="store_false",
                        help="do not assign ipv4 addresses to members")
    # parser.add_argument("--v6_assign_mode", type=bool,
    #                             help="if true, assign ipv6 addresses to "
    #                                  "members")
    parser.add_argument("--route_add",
                        help="list of routes to add, comma separated, "
                             "in the format {target}:{via}, where "
                             "target is {IPV4 Address}/{Netmask bits} "
                             "and via is {IPV4 Address}")
    parser.add_argument("--route_del",
                        help="list of routes to delete.")
    parser.add_argument("--multicast_limit",
                        type=int,
                        help="maximum number of recipients for a "
                             "multicast packet")
    parser.add_argument("--ip_pool_add",
                        help="add a list of ip address pools, in the "
                             "format {start IP}:{end IP} separated by "
                             "commas")
    parser.add_argument("--ip_pool_del",
                        help="delete one or more ip adddress pools "
                             "from the network IP Address pool list.")

    parser.add_argument("--authorized",
                        dest="authorized",
                        action="store_true",
                        help="the member is authorized to participate in the "
                             "network")
    parser.add_argument("--not_authorized",
                        dest="authorized",
                        action="store_false",
                        help="the member is NOT authorized to participate in "
                             "the network")
    parser.add_argument("--enable_active_bridging",
                        dest="active_bridge",
                        action="store_true",
                        help="enable member bridging of other networks")
    parser.add_argument("--disable_active_bridging",
                        dest="active_bridge",
                        action="store_false",
                        help="disable member bridging of other networks")
    parser.add_argument("--ip_add",
                        help="add one or more managed IPs, "
                             "comma-separated")
    parser.add_argument("--ip_del",
                        help="delete one or more managed IP addresses, "
                             "comma-separated")
    parser.add_argument("-v",
                        "--verbose",
                        help="enable debug log output",
                        action="store_true")
    parser.add_argument("-f",
                        "--output_format",
                        help="format of output from commands",
                        choices=["json", "csv", "text"],
                        default="json",
                        dest="format")
    return parser.parse_args(args)


def get_request(url: str, headers: dict, path: str)->dict:
    """
    Perform an HTTP GET request
    :param url: the url to request
    :param headers: a dict containing the ZT Auth header
    :param path: the path at the url to request
    :return: a dict representing the returned JSON object.

    raises a requests.exceptions.HTTPError when th response is not 200

    """
    _url = url + path
    r = requests.get(_url, headers=headers)
    r.raise_for_status()
    return r.json()


def post_request(url: str, headers: dict, path: str, data: dict)->dict:
    """
    Perform an HTTP POST request
    :param url: the url to POST to
    :param headers:a dict containing the ZT auth header
    :param path: the path to POST to
    :param data: a dict containing data to post
    :return: a dict converted from the returned JSON object

    raises a requests.exceptions.HTTPError when the response code is not 200

    """
    _url = url + path
    r = requests.post(_url, data=json.dumps(data), headers=headers)
    r.raise_for_status()
    return r.json()


def delete_request(url: str, headers: dict, path: str)->dict:
    _url = url + path
    r = requests.delete(_url, headers=headers)
    r.raise_for_status()
    return r.json()


def validate_ip_mask(in_ip_mask: str)->bool:
    """
    ensure that in_ip_mask is a string in the form x.x.x.x/y
    :param in_ip_mask:
    :return:
    """
    if "/" not in in_ip_mask:
        logging.error("invalid IP mask: {}, no / before bit mask"
                      .format(in_ip_mask))
        return False
    ip, mask = in_ip_mask.split("/")
    try:
        mask_int = int(mask)
        if mask_int <= 0 or mask_int > 32:
            logging.error("invalid IP mask: {}, bit mask <= 0 or > 32"
                          .format(in_ip_mask))
            return False
    except ValueError:
        logging.error("invalid IP mask: {}, bit mask is not an integer"
                      .format(in_ip_mask))
        return False

    if "." not in ip:
        logging.error("invalid IP mask: {}, no . in IP address"
                      .format(in_ip_mask))
        return False

    octets = ip.split(".")
    if len(octets) != 4:
        logging.error("invalid IP mask : {}, IP does not contain 4 octets"
                      .format(in_ip_mask))
        return False

    prev_octet_int = 1
    for octet in octets:
        try:
            octet_int = int(octet)
            if octet_int < 0 or octet_int > 255:
                logging.error("invalid IP mask: {}, IP octet {} < 0 or > 255"
                              .format(in_ip_mask, octet_int))
                return False
            if octet_int != 0 and prev_octet_int == 0:
                logging.error("invalid IP mask: {}, IP octet not 0, but "
                              "previous octet was 0".format(in_ip_mask))
                return False
            prev_octet_int = octet_int
        except ValueError:
            logging.error("invalid IP mask: {}, IP octet {} not an integer"
                          .format(in_ip_mask, octet))

    return True


def validate_ip_address(in_ip_string: str)->bool:
    """
    validate an IP address string
    :param in_ip_string: a string containing a possible ip address.
    :return: True if the string is a valid IPV4 address
    """
    if "." not in in_ip_string:
        logging.error("invalid IP: {}, no . in IP address"
                      .format(in_ip_string))
        return False

    octets = in_ip_string.split(".")
    if len(octets) != 4:
        logging.error("invalid IP: {}, IP does not contain 4 octets"
                      .format(in_ip_string))
        return False

    prev_octet_int = 1
    for octet in octets:
        try:
            octet_int = int(octet)
            if octet_int < 0 or octet_int > 255:
                logging.error("invalid IP: {}, IP octet {} < 0 or > 255"
                              .format(in_ip_string, octet_int))
                return False
            if octet_int != 0 and prev_octet_int == 0:
                logging.error("invalid IP: {}, IP octet not 0, but "
                              "previous octet was 0".format(in_ip_string))
                return False
            prev_octet_int = octet_int
        except ValueError:
            logging.error("invalid IP: {}, IP octet {} not an integer"
                          .format(in_ip_string, octet))

    return True


def parse_route_string(in_route_string: str)->list:
    """
    Parse a string containing a comma-separated list of route statements in
    the form x.x.x.x/y:x.x.x.x, ..., Z
    :param in_route_string:
    :return:
    """
    route_strings = in_route_string.split(",")
    route_list = []
    for route_string in route_strings:
        if ":" in route_string:
            target, via = route_string.split(":")
            if validate_ip_mask(target) is True \
                    and validate_ip_address(via) is True:
                route_list.append({"target": target, "via": via})
        else:
            if validate_ip_address(route_string) is True:
                route_list.append({"target": route_string, "via": None})
    return route_list


def ip_str_to_byte_array(ip_str: str)->list:
    """
    Convert a string containg an IPV4 address into an array of 4 bytes
    :param ip_str: an ip address string
    :return: a 4-byte list
    """
    out_list = []
    if validate_ip_address(ip_str) is False:
        logging.error("invalid ip address: {}".format(ip_str))
        return out_list
    octets = ip_str.split(".")
    for octet in octets:
        out_list.append(int(octet))
    return out_list


def validate_same_net(ip_str_1: str, ip_str_2: str)->bool:
    """
    Determine if two ip address strings are in the same network.
    :param ip_str_1: an ipv4 address string
    :param ip_str_2: an ipv4 address string
    :return: True if in same net, False if not
    """
    ip_1 = ip_str_to_byte_array(ip_str_1)
    if not ip_1:
        logging.error("invalid ip address: {}".format(ip_str_1))
        return False
    ip_2 = ip_str_to_byte_array(ip_str_2)
    if not ip_2:
        logging.error("invalid ip address: {}".format(ip_str_2))
        return False

    # case 1: first octet should be the same
    if ip_1[0] != ip_2[0]:
        return False

    # case 2: any 0s in the ip should be in the same spot and both should have
    # the same number.
    ip_1_zero_cnt = 0
    ip_2_zero_cnt = 0
    for i in range(0, 4):
        if ip_1[i] == 0 and ip_2[i] != 0:
            return False
        if ip_1[i] == 0:
            ip_1_zero_cnt += 1
        if ip_2[i] == 0:
            ip_2_zero_cnt += 1
    if ip_1_zero_cnt != ip_2_zero_cnt:
        return False

    return True


def ip_bytes_to_int(ip_bytes: list)->int:
    """

    :param ip_bytes:
    :return:
    """
    return (ip_bytes[0] << 24) | (ip_bytes[1] << 16) | (ip_bytes[2] << 8) | \
           ip_bytes[3]


def validate_ip_min_max(min_ip: str, max_ip: str) -> bool:
    """
    Validate that a min and max ip are in fact on the same line in the correct
    order min < max.
    :param min_ip: the lower IP address string
    :param max_ip: the upper IP address tring
    :return: True if min < max. False if min >= max
    """
    min_ip_bytes = ip_str_to_byte_array(min_ip)
    if not min_ip_bytes:
        logging.error("invalid ip address: {}".format(min_ip))
        return False
    max_ip_bytes = ip_str_to_byte_array(max_ip)
    if not max_ip_bytes:
        logging.error("invalid ip address: {}".format(max_ip))
        return False
    min_ip_int = ip_bytes_to_int(min_ip_bytes)
    max_ip_int = ip_bytes_to_int(max_ip_bytes)
    if min_ip_int >= max_ip_int:
        return False
    return True


def parse_ip_pool_string(in_pool_string: str)->list:
    """

    :param in_pool_string:
    :return:
    """
    pool_strings = in_pool_string.split(",")
    pool_list = []
    for pool_string in pool_strings:
        if ":" not in pool_string:
            logging.warning("invalid pool string: {}".format(pool_string))
            continue
        pool_min, pool_max = pool_string.split(":")
        if validate_ip_address(pool_min) is False \
                or validate_ip_address(pool_max) is False:
            logging.warning("invalid pool string: {}".format(pool_string))
            continue
        if validate_same_net(pool_min, pool_max) is False:
            logging.warning("invalid pool string: {}".format(pool_string))
            continue
        if validate_ip_min_max(pool_min, pool_max) is False:
            logging.warning("invalid pool string: {}".format(pool_string))
            continue
        pool_list.append({"ipRangeStart": pool_min, "ipRangeEnd": pool_max})
    return pool_list


def network_command(cmd_line: argparse.Namespace,
                    url: str,
                    headers: dict,
                    network: str,
                    controller: str)->int:
    """
    process "network" commands
    :param controller: optional controller member ID, required when creating a
    new network
    :param network: 10-byte hex string network ID
    :param headers: a dict containing the ZT auth header
    :param url: the url str of the zt controller
    :param cmd_line: an argparse Namespace object containing parsed command
    line arguments
    :return: 0 on success, -1 on failure
    """

    result = {}

    # case 1: list
    # ignore any command line arguments specified and just return a list of
    # networks

    if cmd_line.action == "list":
        result = get_request(url, headers, "network")
    # case 2: get
    elif cmd_line.action == "get":
        if network is None:
            logging.error("network ID not provided as environment variable or "
                          "command line argument")
            return -1
        _path = "network/{}".format(network)
        result = get_request(url, headers, _path)
    # case 3: create
    elif cmd_line.action == "create":
        if controller is None:
            logging.error("controller address not provided as environment "
                          "variable or command line argument")
            return -1
        if cmd_line.name is None:
            logging.error("network name not specified")
            return -1
        _path = "network/{}______".format(controller)
        data = {"name": cmd_line.name}
        result = post_request(url, headers, _path, data)
    # case 4: update
    elif cmd_line.action == "update":
        # first get a copy of the existing one
        if network is None:
            logging.error("network ID not provided as environment variable or "
                          "command line argument")
            return -1
        _path = "network/{}".format(network)
        current_data = get_request(url, headers, _path)
        #   update --> modify a network
        update_data = {}
        # --name: network name
        if cmd_line.name is not None:
            update_data["name"] = cmd_line.name
        # --private/--not_private: access control enabled true/false
        if cmd_line.private is not None:
            update_data["private"] = cmd_line.private
        # --enable_broadcast/--disable_broadcast: enable ethernet
        # ff:ff:ff:ff:ff:ff: true/false
        if cmd_line.broadcast is not None:
            update_data["enableBroadcast"] = cmd_line.broadcast
        # --enable_passive_bridging/--disable_passive_bridging: allow any
        # member to bridge: true/false if cmd_Line.allow_passive_bridging is
        # not None:
        # TODO: according to the docs allow passive bridging is experimental
        # --v4_assign_mode: assign ipv4 addresses to members
        if cmd_line.v4_assign is True:
            update_data["v4AssignMode"] = "zt"
        elif cmd_line.v4_assign is False:
            update_data["v4AssignMode"] = ""
        # --v6_assign_mode: assign ipv6 addresses to members
        # if cmd_line.v6_assign_mode is True:
        # TODO: ipv6 support not tested yet
        # --route-add: add routes target:via, ... target:via
        if cmd_line.route_add is not None:
            # routes to be added should take one of two formats:
            # source route (we are the source of managed IPs etc):
            # {"target": "10.8.10.0/24", "via": null}
            # target route (something is reachable)
            # {"target": "y.y.y.y/zz", "via": x.x.x.x}
            route_list = parse_route_string(cmd_line.route_add)
            update_data["routes"] = route_list
            update_data["routes"].extend(current_data["routes"])
        # --route_del: remove routes: target:via, ... target:via
        if cmd_line.route_del is not None:
            route_list = parse_route_string(cmd_line.route_del)
            new_route_list = []
            for route in current_data["routes"]:
                if route not in route_list:
                    new_route_list.append(route)
            update_data["routes"] = new_route_list
        # --multicast_limit: maximum recipients for a multicast packet
        if cmd_line.multicast_limit is not None:
            update_data["multicastLimit"] = cmd_line.multicast_limit
        # --ip_pool_add: add one or more ip address assignment
        # pools: start:end, ... start:end
        if cmd_line.ip_pool_add is not None:
            pool_list = parse_ip_pool_string(cmd_line.ip_pool_add)
            update_data["ipAssignmentPools"] = pool_list
            update_data["ipAssignmentPools"].extend(
                current_data["ipAssignmentPools"])
        # --ip_pool_del: delete one or more address assignment pools:
        # start:end, ..., start:end
        if cmd_line.ip_pool_del is not None:
            pool_list = parse_ip_pool_string(cmd_line.ip_pool_del)
            new_pool_list = []
            for pool in current_data["ipAssignmentPools"]:
                if pool not in pool_list:
                    new_pool_list.append(pool)
            update_data["ipAssignmentPools"] = new_pool_list
        # --rule_add: add one or more rules: TBD rule, ..., rule
        # --rule_del: delete one or more rules
        # if cmd_line.rule_add is not None:
        #     # TODO: parse rule
        #     # TODO: append to existing rule list
        #     logging.error("--rule_add option not implemented")
        #     return -1
        # if cmd_line.rule_del is not None:
        #     # TODO: parse rules
        #     # TODO: delete matching rules from existing rule list
        #     logging.error("--rule_del option not implemented")
        #     return -1
        _path = "network/{}".format(network)
        result = post_request(url, headers, data=update_data, path=_path)
    # case 5: delete
    elif cmd_line.action == "delete":
        _path = "network/{}".format(network)
        result = delete_request(url, headers, path=_path)

    if cmd_line.format == "json":
        output = json.dumps(result, indent=4, sort_keys=True)
        print(output)
    else:
        print(result)

    return 0


def parse_ip_string(in_ip_string: str)->list:
    """
    Parse a cmd line IP address comma-separated list and return a list of
    strings, one per IP address.
    :param in_ip_string: a string containing comma-separated IPs
    {IP 1},...,{IP N}
    :return: a list of strings, one per IP address
    """
    ip_list = []
    ip_strings = in_ip_string.split(",")
    for ip_string in ip_strings:
        _ip_string = ip_string.strip()
        if validate_ip_address(_ip_string) is True:
            ip_list.append(_ip_string)
        else:
            logging.warning("invalid IP address: {}".format(_ip_string))
    return ip_list


def get_net_ip_pools(url: str, headers: dict, network: str)->list:
    """

    :param url:
    :param headers:
    :param network:
    :return:
    """
    out_list = []
    if network is None:
        logging.error("network ID not provided as environment variable or "
                      "command line argument")
        return out_list
    _path = "network/{}".format(network)
    result = get_request(url, headers, _path)
    return result["ipAssignmentPools"]


def ip_str_to_int(ip_addr: str)->int:
    """
    convert an ip address string to a 32-byte int
    :param ip_addr: an ip address string
    :return:
    """
    # 1 convert string to bytes
    if validate_ip_address(ip_addr) is False:
        logging.error("invalid ip address: {}".format(ip_addr))
        return -1
    ip_bytes = ip_str_to_byte_array(ip_addr)
    if not ip_bytes:
        logging.error("invalid ip address: {}".format(ip_addr))
        return -1
    return ip_bytes_to_int(ip_bytes)


def ips_in_pools(ips: list, pools: list)->bool:
    """
    Check if list of ip address strings is in a list of ip address pools.
    :param ips:
    :param pools:
    :return: Return True if all ips in the list belong to the ip address pools
    """
    for pool in pools:
        min_ip_str = pool["ipRangeStart"]
        max_ip_str = pool["ipRangeEnd"]
        min_ip_int = ip_str_to_int(min_ip_str)
        if min_ip_int == -1:
            logging.error("invalid ip address: {}".format(min_ip_str))
            return False
        max_ip_int = ip_str_to_int(max_ip_str)
        if max_ip_int == -1:
            logging.error("invalid ip address: {}".format(max_ip_str))
        for ip in ips:
            ip_int = ip_str_to_int(ip)
            if ip_int == -1:
                logging.error("invalid ip address: {}".format(ip))
            if ip_int < min_ip_int or ip_int > max_ip_int:
                return False
    return True


def member_command(cmd_line: argparse.Namespace,
                   url: str,
                   headers: dict,
                   network: str,
                   member: str)->int:
    """
    process "member" commands
    :param member: 5-byte hex string optional member ID. Required when modifying the member
    :param network: 10-byte network ID hex string
    :param headers: a dict containing the ZT auth header
    :param url: the target URL
    :param cmd_line: parsed command line arguments
    :return: 0 on succcess; -1 on failure
    """

    if network is None:
        logging.error("network not specified")
        return -1

    result = {}

    # case 1: list
    # /controller/network/5433b56615c0f45c/member
    if cmd_line.action == "list":
        _path = "network/{}/member".format(network)
        result = get_request(url, headers, _path)
    # case 2: get
    # /controller/network/5433b56615c0f45c/member/4a49696d9b
    if cmd_line.action == "get":
        if member is None:
            logging.error("member not specified")
            return -1
        _path = "network/{}/member/{}".format(network, member)
        result = get_request(url, headers, _path)
    # case 3: create
    if cmd_line.action == "create":
        logging.error("member create function not implemented")
        return -1
    # case 4: update
    if cmd_line.action == "update":
        if member is None:
            logging.error("member not specified")
            return -1
        _path = "network/{}/member/{}".format(network, member)
        new_data = {}
        current_data = get_request(url, headers, _path)
        if cmd_line.authorized is True:
            new_data["authorized"] = True
        if cmd_line.authorized is False:
            new_data["authorized"] = False
        if cmd_line.active_bridge is True:
            new_data["activeBridge"] = True
        if cmd_line.active_bridge is False:
            new_data["activeBridge"] = False
        if cmd_line.ip_add is not None:
            new_ips = parse_ip_string(cmd_line.ip_add)
            curr_pools = get_net_ip_pools(url, headers, network)
            if ips_in_pools(new_ips, curr_pools) is True:
                new_data["ipAssignments"] = current_data["ipAssignments"]
                new_data["ipAssignments"].extend(new_ips)
        if cmd_line.ip_del is not None:
            new_ips = []
            del_ips = parse_ip_string(cmd_line.ip_del)
            for ip in current_data["ipAssignments"]:
                if ip not in del_ips:
                    new_ips.append(ip)

            new_data["ipAssignments"] = new_ips
        result = post_request(url, headers, data=new_data, path=_path)
    # case 5: delete
    if cmd_line.action == "delete":
        logging.error("member delete function not implemented")
        return -1

    if cmd_line.format == "json":
        output = json.dumps(result, indent=4, sort_keys=True)
        print(output)
    else:
        print(result)

    return 0


def set_ctx(cmd_line: argparse.Namespace)->():
    if cmd_line.verbose is True:
        logging.basicConfig(format=LOGGING_FMT_STR,
                            datefmt=LOGGING_DATEFMT_STR,
                            level=logging.DEBUG)
    else:
        logging.basicConfig(format=LOGGING_FMT_STR,
                            datefmt=LOGGING_DATEFMT_STR,
                            level=logging.INFO)
    # port
    port = os.environ.get("ZTCC_PORT")
    if port is None:
        port = cmd_line.port

    # host
    host = os.environ.get("ZTCC_HOST")
    if host is None:
        host = cmd_line.host

    # auth token
    auth_token = os.environ.get("ZTCC_AUTH_TOKEN")
    if auth_token is None:
        auth_token = cmd_line.auth_token
    if auth_token is None:
        logging.error("auth token not supplied in environment or command line")
        return -1

    # network ID
    network = os.environ.get("ZTCC_NET")
    if network is None:
        network = cmd_line.network

    # controller ID
    controller = os.environ.get("ZTCC_CONTROLLER")
    if controller is None:
        controller = cmd_line.controller

    # member ID
    member = cmd_line.member

    # build the target url
    url = "http://{}:{}/controller/".format(host, port)
    headers = {'User-Agent': 'ztcc python3',
               'X-ZT1-Auth': auth_token}

    return auth_token, network, controller, member, url, headers


def run()->int:
    """
    main method
    :return:
    """
    # commands
    # 1. process command line
    #   auth token
    #   network/entity
    #   command
    #   arguments
    # 2. check environment for variables
    #   auth token
    #   network/entity id
    # 3. run command
    # 4. display results
    # 5. shell mode
    cmd_line = process_command_line(sys.argv[1:])

    auth_token, network, controller, member, url, headers = set_ctx(cmd_line)

    # get the command provided by the user
    if cmd_line.command == "network":
        return network_command(cmd_line, url, headers, network, controller)
    elif cmd_line.command == "member":
        return member_command(cmd_line, url, headers, network, member)
    else:
        logging.error("invalid command specified: {}"
                      .format(cmd_line["command"]))
        return -1


# ENTRY POINT
if __name__ == "__main__":
    sys.exit(run())

# END OF FILE
