#!/usr/bin/python

# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from Crypto.Cipher import AES
import random
import requests
import socket
import struct
import threading
import time

from . import lakeside_pb2

key = bytearray([0x24, 0x4E, 0x6D, 0x8A, 0x56, 0xAC, 0x87, 0x91, 0x24, 0x43, 0x2D, 0x8B, 0x6C, 0xBC, 0xA2, 0xC4])
iv = bytearray([0x77, 0x24, 0x56, 0xF2, 0xA7, 0x66, 0x4C, 0xF3, 0x39, 0x2C, 0x35, 0x97, 0xE9, 0x3E, 0x57, 0x47])

def get_devices(username, password):
    devices = [];

    client_id = "eufyhome-app"
    client_secret = "GQCpr9dSp3uQpsOMgJ4xQ"

    payload = {'client_id':client_id, 'client_Secret':client_secret, 'email':username, 'password':password}
    r = requests.post("https://home-api.eufylife.com/v1/user/email/login", json=payload)

    token = r.json()['access_token']
    headers = {'token': token, 'category': 'Home'}
    r = requests.get("https://home-api.eufylife.com/v1/device/list/devices-and-groups", headers=headers)
    info = r.json()

    for item in info['items']:
        if item['device'] is not None:
            devices.append({
                'address': item['device']['wifi']['lan_ip_addr'],
                'code': item['device']['local_code'],
                'type': item['device']['product']['product_code'],
                'name': item['device']['alias_name'],
                'id': item['device']['id'],
            })

    return devices

class device:
    def __init__(self, address, code, kind=None):
        self.address = address
        self.code = code
        self.kind = kind
        self.keepalive = None

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.address, 55556))
        self.update()
        if self.keepalive is None:
            self.keepalive = threading.Thread(target=self.ping, args=())
            self.keepalive.daemon = True
            self.keepalive.start()

    def send_packet(self, packet, response):
        cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        raw_packet = packet.SerializeToString()

        for i in range(16 - (len(raw_packet) % 16)):
            raw_packet += b'\0'

        encrypted_packet = cipher.encrypt(raw_packet)

        try:
            self.s.send(encrypted_packet)
        except:
            self.connect()
            self.s.send(encrypted_packet)
            
        if response:
            data = self.s.recv(1024)
            if (len(data) == 0):
                self.connect()
                self.s.send(encrypted_packet)
                data = self.s.recv(1024)
                
            cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
            decrypted_packet = cipher.decrypt(data)

            length = struct.unpack("<H", decrypted_packet[0:2])[0]
            if self.kind == "T1011" or self.kind == "T1012":
                packet.ParseFromString(decrypted_packet[2:length+2])
            elif self.kind == "T1013":
                packet = lakeside_pb2.T1013Packet()
                packet.ParseFromString(decrypted_packet[2:length+2])
            elif self.kind == "T1201" or self.kind == "T1202" or self.kind == "T1203" or self.kind == "T1211":
                packet = lakeside_pb2.T1201Packet()
                packet.ParseFromString(decrypted_packet[2:length+2])
            return packet

        return None

    def get_sequence(self):
        packet = lakeside_pb2.T1012Packet()
        packet.sequence = random.randrange(3000000)
        packet.code = self.code
        packet.ping.type = 0        
        response = self.send_packet(packet, True)
        return response.sequence + 1

    def ping(self):
        while True:
            time.sleep(10)
            self.get_sequence()

class bulb(device):
    def __init__(self, address, code, kind):
        return device.__init__(self, address, code, kind=kind)

    def connect(self):
        return device.connect(self)

    def send_packet(self, packet, response):
        return device.send_packet(self, packet, response)

    def get_sequence(self):
        return device.get_sequence(self)

    def get_status(self):
        packet = lakeside_pb2.T1012Packet()
        packet.sequence = self.get_sequence()
        packet.code = self.code
        packet.bulbinfo.type = 1
        response = self.send_packet(packet, True)
        return response

    def set_state(self, power=None, brightness=None, temperature=None,
                  colors=None):
        if self.kind == "T1011" or self.kind == "T1012":
            packet = lakeside_pb2.T1012Packet()
            packet.bulbinfo.type = 0
            packet.bulbinfo.packet.unknown1 = 100
            packet.bulbinfo.packet.bulbset.command = 7
            if power != None:
                self.power = power
                packet.bulbinfo.packet.bulbset.power = power
            if brightness != None:
                self.brightness = brightness
                packet.bulbinfo.packet.bulbset.values.brightness=brightness
            if temperature != None:
                self.temperature = temperature
                packet.bulbinfo.packet.bulbset.values.temperature=temperature
        else:
            self.colors = colors
            packet = lakeside_pb2.T1013Packet()
            packet.bulbinfo.type = 0
            packet.bulbinfo.packet.unknown1 = 10
            packet.bulbinfo.packet.control.command = 7
            if power != None:
                self.power = power
                packet.bulbinfo.packet.control.power = power
            if colors != None:
                packet.bulbinfo.packet.control.color = 1
                packet.bulbinfo.packet.control.colors.red = colors[0]
                packet.bulbinfo.packet.control.colors.green = colors[1]
                packet.bulbinfo.packet.control.colors.blue = colors[2]
                if brightness != None:
                    self.brightness = brightness
                packet.bulbinfo.packet.control.colors.brightness = self.brightness
            else:
                packet.bulbinfo.packet.control.color = 0
                if brightness != None:
                    self.brightness = brightness
                if temperature != None:
                    self.temperature = temperature

                packet.bulbinfo.packet.control.values.brightness = self.brightness
                packet.bulbinfo.packet.control.values.temperature = self.temperature
                packet.bulbinfo.packet.control.power = self.power
        packet.sequence = self.get_sequence()
        packet.code = self.code
        self.send_packet(packet, False)

    def update(self):
        response = self.get_status()
        if self.kind == "T1011" or self.kind == "T1012":
            self.brightness = response.bulbinfo.packet.bulbstate.values.brightness
            self.temperature = response.bulbinfo.packet.bulbstate.values.temperature
            self.power = response.bulbinfo.packet.bulbstate.power
            self.colors = None
        elif self.kind == "T1013":
            self.power = response.bulbinfo.packet.info.power
            if response.bulbinfo.packet.info.color == 1:
                self.brightness = response.bulbinfo.packet.info.colors.brightness
                self.colors = []
                self.colors.append(response.bulbinfo.packet.info.colors.red)
                self.colors.append(response.bulbinfo.packet.info.colors.green)
                self.colors.append(response.bulbinfo.packet.info.colors.blue)
                self.temperature = 50
            else:
                self.brightness = response.bulbinfo.packet.info.values.brightness
                self.temperature = response.bulbinfo.packet.info.values.temperature
                self.colors = None

    def set_power(self, power):
        self.set_state(power=power)

    def set_brightness(self, brightness):
        self.set_state(brightness=brightness)

    def set_temperature(self, temperature):
        self.set_state(brightness=self.brightness, temperature=temperature)

    def set_colors(self, colors):
        self.set_state(brightness=self.brightness, colors=colors)

class switch(device):
    def __init__(self, address, code, kind):
        return device.__init__(self, address, code, kind)

    def connect(self):
        return device.connect(self)

    def send_packet(self, packet, response):
        return device.send_packet(self, packet, response)

    def get_sequence(self):
        return device.get_sequence(self)

    def get_status(self):
        packet = lakeside_pb2.T1201Packet()
        packet.sequence = self.get_sequence()
        packet.code = self.code
        packet.switchinfo.type = 1
        response = self.send_packet(packet, True)
        return response

    def update(self):
        response = self.get_status()
        self.power = response.switchinfo.packet.switchstatus.power

    def set_state(self, power):
        packet = lakeside_pb2.T1201Packet()
        packet.switchinfo.type = 0
        packet.switchinfo.packet.unknown1 = 100
        packet.switchinfo.packet.switchset.command = 7
        packet.switchinfo.packet.switchset.state = power
        packet.sequence = self.get_sequence()
        packet.code = self.code
        self.send_packet(packet, False)
