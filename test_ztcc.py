import argparse
import re

import sys
import pytest
import yaml

import ztcc

# TODO: load a yaml file with test data

# def set_cmd_line(cmd_line: list)->argparse.Namespace:
#     pass


# def run_tests():
#     pass
#
# def run()->int:
#     run_tests()
#     return 0
#
# if __name__ == "__main__":
#     sys.exit(run())


@pytest.fixture
def test_data():
    with open("test_data.yml", "r") as fd:
        yaml_data = fd.read()
        _test_data = yaml.load(yaml_data)
        return _test_data


# TODO: test process_command_line
# TODO: test set_ctx

#
# functional tests
#

# network list --auth_token {AUTH_TOKEN}
def test_network_list(test_data):
    args = ["network", "list", "--auth_token", test_data["auth_token"], ]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0


# network get --auth_token {AUTH TOKEN} --network {NETWORK ID}
def test_network_get(test_data):
    args = ["network", "get", "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0


# network create --auth_token AUTH_TOKEN --controller CONTROLLER_ID
# network delete --auth_token AUTH_TOKEN --network NETWORK_ID
def test_create_delete_network(test_data, capsys):
    args = ["network",
            "create",
            "--auth_token", test_data["auth_token"],
            "--controller", test_data["controllers"][0],
            "--name", test_data["test_network_name"]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0

    cap = capsys.readouterr()
    m = re.search('("id": ")([a-f0-9]{16})', cap.out, re.MULTILINE)
    net_to_delete = m.group(2)
    args = ["network",
            "delete",
            "--auth_token", test_data["auth_token"],
            "--network", net_to_delete]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --name NETWORK_NAME
def test_update_net_name(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--name", test_data["test_network_name"]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()
    assert test_data["test_network_name"] in cap.out


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --not_private
def test_update_net_not_private(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--not_private"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()
    assert '"private": false' in cap.out


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --private
def test_update_net_private(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--private"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()
    assert '"private": true' in cap.out


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --enable_broadcast
def test_net_enable_broadcast(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--enable_broadcast"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()
    assert '"enableBroadcast": true' in cap.out


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --disable_broadcast
def test_net_disable_broadcast(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--disable_broadcast"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()
    assert '"enableBroadcast": false' in cap.out


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --enable_v4_assign
def test_net_enable_v4_assign(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--enable_v4_assign"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()
    m = re.search(r"v4AssignMode.{,16}zt.{,4}true", cap.out, re.MULTILINE | re.DOTALL)
    assert m


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --disable_v4_assign
def test_net_disable_v4_assign(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--disable_v4_assign"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()
    m = re.search(r"v4AssignMode.{,16}zt.{,4}false", cap.out, re.MULTILINE | re.DOTALL)
    assert m


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --ip_pool_add 10.99.99.1:10.99.99.254
def test_net_add_pool(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--ip_pool_add", test_data["test_pools"][0]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()

    # TODO: add assertion for presence of pool in output
    # m = re.search(r"v4AssignMode.{,16}zt.{,4}false", cap.out, re.MULTILINE | re.DOTALL)
    # assert m

# TODO: test adding multiple pool entries


# network update --auth_token AUTH_TOKEN --network NETWORK_ID  --ip_pool_del POOL_START_IP:POOL_END_IP
def test_net_del_pool(test_data, capsys):
    args = ["network",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--ip_pool_del", test_data["test_pools"][0]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, controller)
    assert result == 0
    cap = capsys.readouterr()

    # TODO: add assertion for absence of pool in output


# TODO: test removing multiple pool entries
# TODO: test adding one and multiple external routes
# TODO: test deleting one and multiple external routes


# member list --auth_token AUTH_TOKEN --network NETWORK_ID
def test_list_members(test_data, capsys):
    args = ["member",
            "list",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, member)
    assert result == 0

    # TODO: assert length of list > 0


def test_get_member(test_data, capsys):
    args = ["member",
            "get",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--member", test_data["members"][0]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, member)
    assert result == 0

    # TODO: assert member id info


# member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --not_authorized
def test_deauth_member(test_data, capsys):
    args = ["member",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--member", test_data["members"][0],
            "--not_authorized"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, member)
    assert result == 0


# member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --authorized
def test_auth_member(test_data, capsys):
    args = ["member",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--member", test_data["members"][0],
            "--authorized"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, member)
    assert result == 0


# member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --enable_active_bridging
def test_member_en_bridging(test_data, capsys):
    args = ["member",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--member", test_data["members"][0],
            "--enable_active_bridging"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, member)
    assert result == 0


# member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --disable_active_bridging
def test_member_dis_bridging(test_data, capsys):
    args = ["member",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--member", test_data["members"][0],
            "--disable_active_bridging"]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, member)
    assert result == 0


# member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --ip_add MANAGED_IP
def test_member_add_ip(test_data, capsys):
    args = ["member",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--member", test_data["members"][0],
            "--ip_add", test_data["test_ips"][0]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, member)
    assert result == 0


# member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --ip_add MANAGED_IP
def test_member_del_ip(test_data, capsys):
    args = ["member",
            "update",
            "--auth_token", test_data["auth_token"],
            "--network", test_data["networks"][0],
            "--member", test_data["members"][0],
            "--ip_del", test_data["test_ips"][0]]
    cmd_line = ztcc.process_command_line(args)
    auth_token, network, controller, member, url, headers = \
        ztcc.set_ctx(cmd_line)
    result = ztcc.network_command(cmd_line, url, headers, network, member)
    assert result == 0

# END OF FILE
