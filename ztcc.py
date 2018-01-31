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
# -- tabular output
# -- plain text
# -- comma-separated data
# -- json
# -- raw

# IMPORTS
import argparse
import json

import logging

import os

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
def process_command_line():
    """
    --auth_token
    --network
    --member
    {command}
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
    parser.add_argument("--name", help="network name")
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
    parser.add_argument("--route_set",
                                help="list of routes to set. Clears existing "
                                     "route list")
    parser.add_argument("--route_del", help="list of routes to delete.")
    parser.add_argument("--multicast_limit", type=int,
                                help="maximum number of recipients for a "
                                     "multicast packet")
    parser.add_argument("--ip_pool_add",
                                help="add a list of ip address pools, in the "
                                     "format {start IP}:{end IP} separated by "
                                     "commas")
    parser.add_argument("--ip_pool_set",
                                help="set the list of ip address pools. Clears "
                                     "the existing IP address pool list.")
    parser.add_argument("--ip_pool_del",
                                help="delete one or more ip adddress pools "
                                     "from the network IP Address pool list.")

    parser.add_argument("--authorized",
                        dest="authorized",
                        action="store_true",
                        help="the member is authorized to participate in the network")
    parser.add_argument("--not_authorized",
                        dest="authorized",
                        action="store_false",
                        help="the member is NOT authorized to participate in the network")
    parser.add_argument("--enable_active_bridging",
                        dest="active_bridge",
                        action="store_true",
                        help="enable member bridging of other networks")
    parser.add_argument("--disable_active_bridging",
                        dest="active_bridge",
                        action="store_false",
                        help="disable member bridging of other networks")
    parser.add_argument("--ip_add",
                               help="add one or more managed IPs, comma-separated")
    parser.add_argument("--ip_set",
                               help="set the list of managed IP addresses, comma-separated")
    parser.add_argument("--ip_del",
                               help="delete one or more managed IP addresses, comma-separated")

    return parser.parse_args()


def get_request(url, headers, path):
    # TODO: check for non-200 response codes
    req = urllib.request.Request(url + path, headers=headers)
    with urllib.request.urlopen(req) as response:
        result = response.read().decode("utf-8")
        result = json.loads(result)
        return result


def post_request(url, headers, path, data):
    # TODO: check for non-200 response codes
    # if data is not None:
    #     _data = urllib.parse.urlencode(data)
    #     _data = _data.encode('ascii')
    #     req = urllib.request.Request(url + path,
    #                                  data=_data,
    #                                  headers=headers,
    #                                  method="POST")
    # else:
    #     req = urllib.request.Request(url + path, headers=headers, method="POST")
    # with urllib.request.urlopen(req) as response:
    #     result = response.read().decode("utf-8")
    #     result = json.loads(result)
    #     return result
    _url = url + path
    r = requests.post(_url, data=json.dumps(data), headers=headers)
    logging.debug("response: %s", r)
    return r.json()


def parse_route_string(in_route_string: str)->list:
    """

    :param in_route_string:
    :return:
    """
    route_strings = in_route_string.split(",")
    route_list = []
    for route_string in route_strings:
        if ":" in route_string:
            target, via = route_string.split(":")
            # TODO: verify that target is an IP address/Mask
            # TODO: verify that via is an IP address
            route_list.append({"target": target, "via": via})
        else:
            route_list.append({"target": route_string, "via": None})
    return route_list


def parse_ip_pool_string(in_pool_string: str)->list:
    """

    :param in_pool_string:
    :return:
    """
    pool_strings = in_pool_string.split(",")
    pool_list = []
    for pool_string in pool_strings:
        pool_min, pool_max = pool_string.split(":")
        # TODO: verify that pool_min and pool_max are valid IPv4 strings
        # TODO: verify that pool_min and pool_max are in the same network
        # TODO: verify that pool_min is less than pool_max
        pool_list.append({"ipRangeStart": pool_min, "ipRangeEnd": pool_max})
    return pool_list

def network_command(cmd_line, url, headers, network, controller)->int:
    """
    process "network" commands
    :param cmd_line:
    :return:
    """
    # network
    #   list --> list network, return array of 16-digit net ids, /controller/network
    #   get --> get a network by its id
    #   create --> create a network, member id assumed to be controller id, /controller/network/{member_id}______
    #   delete --> delete a network

    # case 1: list
    # ignore any command line arguments specified and just return a list of networks
    # curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network
    if cmd_line.action == "list":
        result = get_request(url, headers, "network")
        print(result)
    # case 2: get
    # curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network/5433b56615c0f45c
    elif cmd_line.action == "get":
        if network is None:
            logging.error("network ID not provided as environment variable or command line argument")
            return -1
        _path = "network/{}".format(network)
        result = get_request(url, headers, _path)
        print(result)
    # case 3: create
    elif cmd_line.action == "create":
        if controller is None:
            logging.error("controller address not provided as environment variable or command line argument")
            return -1
        if cmd_line.name is None:
            logging.error("no network name not specified")
            return -1
        _path = "network/{}______".format(controller)
        # TODO: transform into post request, include network name
        data = {"name": cmd_line.name}
        result = post_request(url, headers, _path, data)
        print(result)
    # case 4: update
    elif cmd_line.action == "update":
        # first get a copy of the existing one
        if network is None:
            logging.error("network ID not provided as environment variable or command line argument")
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
        # --enable_broadcast/--disable_broadcast: enable ethernet ff:ff:ff:ff:ff:ff: true/false
        if cmd_line.broadcast is not None:
            update_data["enableBroadcast"] = cmd_line.broadcast
        # --enable_passive_bridging/--disable_passive_bridging: allow any member to bridge: true/false
        #if cmd_Line.allow_passive_bridging is not None:
        # TODO: according to the docs allow passive bridging is experimental
        # --v4_assign_mode: assign ipv4 addresses to members
        if cmd_line.v4_assign is True:
            update_data["v4AssignMode"] = "zt"
        elif cmd_line.v4_assign is False:
            update_data["v4AssignMode"] = ""
        # --v6_assign_mode: assign ipv6 addresses to members
        # if cmd_line.v6_assign_mode is True:
        # TODO: ipv6 support not tested yet
        if cmd_line.route_add is not None and cmd_line.route_set is not None:
            logging.error("--route-add and --route-set options are mutually exclusive")
            return -1
        if cmd_line.route_del is not None and cmd_line.route_set is not None:
            logging.error("--route-del and --route-set options are mutually exclusive")
            return -1
        #       --route-add: add routes target:via, ... target:via
        if cmd_line.route_add is not None:
            # routes to be added should take one of two formats:
            # source route (we are the source of managed IPs etc): {"target": "10.8.10.0/24", "via": null}
            # target route (something is reachable) {"target": "y.y.y.y/zz", "via": x.x.x.x}
            # when a user adds one or more routes they should do so with a comma separated list route1, route2, ... routeN
            # each route should be in the format {target ip}/{target mask}:{via ip}
            route_list = parse_route_string(cmd_line.route_add)
            update_data["routes"] = route_list
            update_data["routes"].extend(current_data["routes"])
        # --route-set: set the route list: target:via, ... target:via
        if cmd_line.route_set is not None:
            route_list = parse_route_string(cmd_line.route_set)
            update_data["routes"] = route_list
        # --route_del: remove routes: target:via, ... target:via
        if cmd_line.route_del is not None:
            route_list = parse_route_string(cmd_line.route_del)
            new_route_list = []
            for route in current_data["routes"]:
                if route not in route_list:
                    new_route_list.append(route)
            update_data["routes"] = new_route_list
        #       --multicast_limit: maximum recipients for a multicast packet
        if cmd_line.multicast_limit is not None:
            update_data["multicastLimit"] = cmd_line.multicast_limit
        if cmd_line.ip_pool_add is not None and cmd_line.ip_pool_set is not None:
            logging.error("--ip_pool_add and --ip_pool_set options are mutually exclusive")
            return -1
        if cmd_line.ip_pool_del is not None and cmd_line.ip_pool_set is not None:
            logging.error("--ip_pool_del and --ip_pool_set options are mutually exclusive")
            return -1
        #       --ip_pool_add: add one or more ip address assignment pools: start:end, ... start:end
        if cmd_line.ip_pool_add is not None:
            pool_list = parse_ip_pool_string(cmd_line.ip_pool_add)
            update_data["ipAssignmentPools"] = pool_list
            update_data["ipAssignmentPools"].extend(current_data["ipAssignmentPools"])
         #       --ip_pool_set: set the list of ip address assignments: start:end, ..., start:end
        if cmd_line.ip_pool_set is not None:
            pool_list = parse_ip_pool_string(cmd_line.ip_pool_set)
            update_data["ipAssignmentPools"] = pool_list
        #       --ip_pool_del: delete one or more address assignment pools: start:end, ..., start:end
        if cmd_line.ip_pool_del is not None:
            pool_list = parse_ip_pool_string(cmd_line.ip_pool_del)
            new_pool_list = []
            for pool in current_data["ipAssignmentPools"]:
                if pool not in pool_list:
                    new_pool_list.append(pool)
            update_data["ipAssignmentPools"] = new_pool_list
        #       --rule_add: add one or more rules: TBD rule, ..., rule
        #       --rule_set: set the list of rules
        #       --rule_del: delete one or more rules
        # if cmd_line.rule_add is not None and cmd_line.rule_set is not None:
        #     logging.error("--rule_add and --rule_set are mutually exclusive")
        #     return -1
        # if cmd_line.rule_det is not None and cmd_line.rule_set is not None:
        #     logging.error("--rule_del and --rule_set are mutually exclusive")
        #     return -1
        # if cmd_line.rule_add is not None:
        #     # TODO: parse rule
        #     # TODO: append to existing rule list
        #     logging.error("--rule_add option not implemented")
        #     return -1
        # if cmd_line.rule_set is not None:
        #     # TODO: parse rule
        #     # TODO: set existing rule list
        #     logging.error("--rule_set option not implemented")
        #     return -1
        # if cmd_line.rule_del is not None:
        #     # TODO: parse rules
        #     # TODO: delete matching rules from existing rule list
        #     logging.error("--rule_del option not implemented")
        #     return -1
        _path = "network/{}".format(network)
        result = post_request(url, headers, data=update_data, path=_path)
        print(result)

    # case 5: delete
    elif cmd_line.action == "delete":
        logging.error("network delete not implemented")
        return -1

    return 0


def parse_ip_string(in_ip_string: str)->list:
    """

    :param in_ip_string:
    :return:
    """
    ip_list = []
    ip_strings = in_ip_string.split(",")
    for ip_string in ip_strings:
        # TODO: validate IP address
        ip_list.append(ip_string)
    return ip_list


def member_command(cmd_line, url, headers, network, member)->int:
    """
    process "member" commands
    :param cmd_line:
    :return:
    """

    if network is None:
        logging.error("network not specified")
        return -1

    # case 1: list
    # /controller/network/5433b56615c0f45c/member
    if cmd_line.action == "list":
        _path = "network/{}/member".format(network)
        result = get_request(url, headers, _path)
        print(result)
    # case 2: get
    # /controller/network/5433b56615c0f45c/member/4a49696d9b
    if cmd_line.action == "get":
        if member is None:
            logging.error("member not specified")
            return -1
        _path = "network/{}/member/{}".format(network, member)
        result = get_request(url, headers, _path)
        print(result)
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
        # TODO: validate IP address
        # TODO: check that IP address in served managed IP ranges
        if cmd_line.ip_add is not None:
            new_data["ipAssignments"] = current_data["ipAssignments"]
            new_data["ipAssignments"].extend(parse_ip_string(cmd_line.ip_add))
        if cmd_line.ip_set is not None:
            new_data["ipAssignments"] = parse_ip_string(cmd_line.ip_set)
        if cmd_line.ip_del is not None:
            new_ips = []
            del_ips = parse_ip_string(cmd_line.ip_del)
            for ip in current_data["ipAssignments"]:
                if ip not in del_ips:
                    new_ips.append(ip)
            new_data["ipAssignments"] = new_ips
        result = post_request(url, headers, data=new_data, path=_path)
        print(result)
    # case 5: delete
    if cmd_line.action == "delete":
        logging.error("member delete function not implemented")
        return -1
    return 0


def run():
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
    cmd_line = process_command_line()

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
    # curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network
    url = "http://{}:{}/controller/".format(host, port)
    headers = {'User-Agent': 'ztcc python3',
               'X-ZT1-Auth': auth_token}

    # get the command provided by the user
    if cmd_line.command == "network":
        return network_command(cmd_line, url, headers, network, controller)
    elif cmd_line.command == "member":
        return member_command(cmd_line, url, headers, network, member)
    else:
        logging.error("invalid command specified: {}".format(cmd_line["command"]))
        return -1


# ENTRY POINT
if __name__ == "__main__":
    sys.exit(run())

# END OF FILE
