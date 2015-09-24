#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import errno
import traceback
import socket
import logging
import json
import collections
import signal
import sys
import os
import datetime

from shadowsocks import common, eventloop, tcprelay, udprelay, asyncdns, shell


BUF_SIZE = 1506
STAT_SEND_LIMIT = 100
LIMIT_MULTIPLE = 1048576  # 1M = 1048576 BYTES

class Manager(object):

    def __init__(self, config):
        self._config = config
        self._port_info = {}
        self._relays = {}  # (tcprelay, udprelay)
        self._loop = eventloop.EventLoop()
        self._dns_resolver = asyncdns.DNSResolver()
        self._dns_resolver.add_to_loop(self._loop)

        self._last_day = datetime.date.today().day
        self._statistics = collections.defaultdict(int)
        # 使用 _statistics_sum 来记录每天使用的流量的总量，每天凌晨刷新
        self._statistics_sum = collections.defaultdict(int)

        self._control_client_addr = None
        self._control_client_url = None
        try:
            manager_address = config['manager_address']
            if ':' in manager_address:
                addr = manager_address.rsplit(':', 1)
                addr = addr[0], int(addr[1])
                addrs = socket.getaddrinfo(addr[0], addr[1])
                if addrs:
                    family = addrs[0][0]
                else:
                    logging.error('invalid address: %s', manager_address)
                    exit(1)
            else:
                addr = manager_address
                self._control_client_url = addr
                family = socket.AF_UNIX
            self._control_socket = socket.socket(family,
                                                 socket.SOCK_DGRAM)
            self._control_socket.bind(addr)
            self._control_socket.setblocking(False)
        except (OSError, IOError) as e:
            logging.error(e)
            logging.error('can not bind to manager address')
            exit(1)
        self._loop.add(self._control_socket,
                       eventloop.POLL_IN, self)
        self._loop.add_periodic(self.handle_periodic)

        port_password = config['port_password']
        port_limit = config['port_limit']

        del config['port_password']
        del config['port_limit']
        del config['server_port']

        if port_limit is None:
            port_limit = {}

        for port, password in port_password.items():
            a_config = config.copy()
            a_config['server_port'] = int(port)
            a_config['password'] = password
            if port in port_limit:
                a_config['limit'] = int(port_limit[port]) * LIMIT_MULTIPLE
            self.add_user(a_config)

    def add_user(self, config):
        port = int(config['server_port'])
        if port in self._port_info:
            logging.error("user already exists at %s:%d" % (config['server'], port))
            return
        logging.info("adding user at %s:%d" % (config['server'], port))
        self._port_info[port] = config
        self.add_port(config)

    def remove_user(self, config):
        port = int(config['server_port'])
        if port not in self._port_info:
            logging.error("user not exist at %s:%d" % (config['server'], port))
            return
        logging.info("removing user at %s:%d" % (config['server'], port))
        if port in self._relays:
            self.remove_port(config)
        del self._port_info[port]

    def add_port(self, config):
        port = int(config['server_port'])
        servers = self._relays.get(port, None)
        if servers:
            logging.error("port already opened at %s:%d" % (config['server'], port))
            return
        logging.info("opening port at %s:%d" % (config['server'], port))
        t = tcprelay.TCPRelay(config, self._dns_resolver, False,
                              self.stat_callback)
        u = udprelay.UDPRelay(config, self._dns_resolver, False,
                              self.stat_callback)
        t.add_to_loop(self._loop)
        u.add_to_loop(self._loop)
        self._relays[port] = (t, u)

    def remove_port(self, config):
        port = int(config['server_port'])
        servers = self._relays.get(port, None)
        if servers:
            logging.info("closing port at %s:%d" % (config['server'], port))
            t, u = servers
            t.close(next_tick=False)
            u.close(next_tick=False)
            del self._relays[port]
        else:
            logging.error("port not open at %s:%d" % (config['server'], port))

    def handle_event(self, sock, fd, event):
        if sock == self._control_socket and event == eventloop.POLL_IN:
            data, self._control_client_addr = sock.recvfrom(BUF_SIZE)
            parsed = self._parse_command(data)
            if parsed:
                command, config = parsed
                a_config = self._config.copy()
                if config:
                    # let the command override the configuration file
                    a_config.update(config)
                command = command.strip()

                # 加一些检测命令的语句，防止错误的指令轻易地使服务器崩溃
                try:
                    if command == 'add':
                        assert 'server_port' in a_config
                        assert 'password' in a_config
                        assert type(a_config['server_port']) is int
                        assert type(a_config['password']) is str
                        self.add_user(a_config)
                        self._send_control_data(b'ok')
                    elif command == 'remove':
                        assert 'server_port' in a_config
                        assert type(a_config['server_port']) is int
                        self.remove_user(a_config)
                        self._send_control_data(b'ok')
                    elif command == 'ping':
                        self._send_control_data(b'pong')
                    else:
                        logging.error('unknown command %s', command)
                        self._send_control_data(b'unknown command')
                except AssertionError:
                    self._send_control_data(b'error command')
            else:
                self._send_control_data(b'error command')

    def _parse_command(self, data):
        # commands:
        # add: {"server_port": 8000, "password": "foobar"}
        # remove: {"server_port": 8000"}
        data = common.to_str(data)
        parts = data.split(':', 1)
        if len(parts) < 2:
            return data, None
        command, config_json = parts
        try:
            config = shell.parse_json_in_str(config_json)
            return command, config
        except Exception as e:
            logging.error(e)
            return None

    def stat_callback(self, port, data_len):
        self._statistics[port] += data_len
        self._statistics_sum[port] += data_len

    def handle_periodic(self):

        r = {}
        i = 0

        def send_data(data_dict):
            if data_dict:
                # use compact JSON format (without space)
                data = common.to_bytes(json.dumps(data_dict,
                                                  separators=(',', ':')))
                self._send_control_data(b'stat: ' + data)

        if self._control_client_addr:
            for k, v in self._statistics.items():
                r[k] = v
                i += 1
                # split the data into segments that fit in UDP packets
                if i >= STAT_SEND_LIMIT:
                    send_data(r)
                    r.clear()
            send_data(r)
        self._statistics.clear()

        day = datetime.date.today().day
        if day != self._last_day:
            self._statistics_sum.clear()
            self._last_day = day
            # reopen those blocked port
            for k, v in self._port_info.items():
                if k not in self._relays:
                    self.add_port(v)

        # check limits, only check those working relays
        for port in self._relays.keys():
            a_config = self._port_info[port]
            if self._statistics_sum[port] > a_config.get('limit', float("Inf")):
                logging.info('port %s exceed limit' % port)
                # them close this port
                self.remove_port(a_config)
                self._send_control_data(b'close port %s' % port)

    def _send_control_data(self, data):
        if self._control_client_addr:
            try:
                self._control_socket.sendto(data, self._control_client_addr)
            except (socket.error, OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()

    def handle_sigint(self, signum, _):
        try:
            if self._control_client_url:
                os.remove(self._control_client_url)
        except OSError:
            pass
        sys.exit(1)

    def run(self):
        # fix
        signal.signal(signal.SIGINT, self.handle_sigint)

        self._loop.run()


def run(config):
    Manager(config).run()


def test():
    import time
    import threading
    import struct
    from shadowsocks import encrypt

    logging.basicConfig(level=5,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    enc = []
    eventloop.TIMEOUT_PRECISION = 1

    def run_server():
        config = {
            'server': '127.0.0.1',
            'local_port': 1081,
            'port_password': {
                '8381': 'foobar1',
                '8382': 'foobar2'
            },
            'method': 'aes-256-cfb',
            'manager_address': '127.0.0.1:6001',
            'timeout': 60,
            'fast_open': False,
            'verbose': 2
        }
        manager = Manager(config)
        enc.append(manager)
        manager.run()

    t = threading.Thread(target=run_server)
    t.start()
    time.sleep(1)
    manager = enc[0]
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.connect(('127.0.0.1', 6001))

    # test add and remove
    time.sleep(1)
    cli.send(b'add: {"server_port":7001, "password":"asdfadsfasdf"}')
    time.sleep(1)
    assert 7001 in manager._relays
    data, addr = cli.recvfrom(1506)
    assert b'ok' in data

    cli.send(b'remove: {"server_port":8381}')
    time.sleep(1)
    assert 8381 not in manager._relays
    data, addr = cli.recvfrom(1506)
    assert b'ok' in data
    logging.info('add and remove test passed')

    # test statistics for TCP
    header = common.pack_addr(b'google.com') + struct.pack('>H', 80)
    data = encrypt.encrypt_all(b'asdfadsfasdf', 'aes-256-cfb', 1,
                               header + b'GET /\r\n\r\n')
    tcp_cli = socket.socket()
    tcp_cli.connect(('127.0.0.1', 7001))
    tcp_cli.send(data)
    tcp_cli.recv(4096)
    tcp_cli.close()

    data, addr = cli.recvfrom(1506)
    data = common.to_str(data)
    assert data.startswith('stat: ')
    data = data.split('stat:')[1]
    stats = shell.parse_json_in_str(data)
    assert '7001' in stats
    logging.info('TCP statistics test passed')

    # test statistics for UDP
    header = common.pack_addr(b'127.0.0.1') + struct.pack('>H', 80)
    data = encrypt.encrypt_all(b'foobar2', 'aes-256-cfb', 1,
                               header + b'test')
    udp_cli = socket.socket(type=socket.SOCK_DGRAM)
    udp_cli.sendto(data, ('127.0.0.1', 8382))
    tcp_cli.close()

    data, addr = cli.recvfrom(1506)
    data = common.to_str(data)
    assert data.startswith('stat: ')
    data = data.split('stat:')[1]
    stats = json.loads(data)
    assert '8382' in stats
    logging.info('UDP statistics test passed')

    manager._loop.stop()
    t.join()


if __name__ == '__main__':
    test()
