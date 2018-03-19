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
import lakeside.lakeside_proto
import time
import struct

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
        devices.append({'address': item['device']['wifi']['lan_ip_addr'], 'code': item['device']['local_code'], 'type': item['device']['product']['product_code'], 'name': item['device']['alias_name']})

    return devices

class bulb:
    def __init__(self, address, code):
        self.address = address
        self.code = code

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.address, 55556))
        self.update()

    def send_packet(self, packet, response):
        cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        raw_packet = packet.SerializeToString()

        for i in range(16 - (len(raw_packet) % 16)):
            raw_packet += b'\0'

        encrypted_packet = cipher.encrypt(raw_packet)

        self.s.send(encrypted_packet)
        if response:
            data = self.s.recv(1024)

            cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
            decrypted_packet = cipher.decrypt(data)

            length = struct.unpack("<H", decrypted_packet[0:2])[0]
            packet.ParseFromString(decrypted_packet[2:length+2])
            return packet

        return None

    def get_sequence(self):
        packet = lakeside_proto.EufyPacket()
        packet.sequence = random.randrange(3000000)
        packet.code = self.code
        packet.ping.type = 0        
        response = self.send_packet(packet, True)
        return response.sequence + 1
    
    def set_state(self, power=None, brightness=None, temperature=None):
        packet = lakeside_proto.EufyPacket()
        packet.sequence = self.get_sequence()
        packet.code = self.code
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
        self.send_packet(packet, False)

    def get_status(self):
        packet = lakeside_proto.EufyPacket()
        packet.sequence = self.get_sequence()
        packet.code = self.code
        packet.bulbinfo.type = 1
        response = self.send_packet(packet, True)
        return response

    def update(self):
        response = self.get_status()
        self.brightness = response.bulbinfo.packet.bulbstate.values.brightness
        self.temperature = response.bulbinfo.packet.bulbstate.values.temperature
        self.power = response.bulbinfo.packet.bulbstate.power

    def set_power(self, power):
        self.set_state(power=power)

    def set_brightness(self, brightness):
        self.set_state(brightness=brightness)

    def set_temperature(self, temperature):
        self.set_state(brightness=self.brightness, temperature=temperature)
