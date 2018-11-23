#!/usr/bin/env python

# Copyright (c) 2014, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.



import sys
import os
import argparse
import logging
from slacker import Slacker

slack = Slacker('xoxb-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]

from pandevice.base import PanDevice
from pandevice.panorama import Panorama


def reg_clear():
    device.userid.clear_registered_ip()
    message = (f'Cleared all registered tags')
    print(message)
    slack.chat.post_message('#paloaltonetworks', message)

def show_list():
        
        all_tags_by_ip = device.userid.get_registered_ip()
        #print(all_tags_by_ip)
        try:
                # Print the tags for the requested IP
            #print(all_tags_by_ip)  
            for x in all_tags_by_ip:
                    message = (f'Current Registered IP/TAG: {x}{all_tags_by_ip[x]}') 
                    print(message)
                    slack.chat.post_message('#paloaltonetworks', message, username='@PANFIREWALL-BOT')
                    

            if not all_tags_by_ip:
                message = ('No IPs registered')
                print(message)
                slack.chat.post_message('#paloaltonetworks', message, username='@PANFIREWALL-BOT')

            logging.info(all_tags_by_ip)
            #print(f'{ip} is registered to: {all_tags_by_ip[ip]}')
        except KeyError:
                # There were no tags for that I4
                # P
            logging.info("No tags for IP: %s" % ip)
            #print(f'No tags registered')

def unregister(ip,tags):
    device.userid.unregister(ip, tags.split(',')) 
    message = (f'Unregistered IP/TAG: ({ip})({tags.split(",")}) to {hostname}')
    print(message)
    slack.chat.post_message('#paloaltonetworks', message, username='@Lab-Firewall')

def register(ip,tags):
    device.userid.register(ip, tags.split(','))
    message = (f'Registered IP/TAG: ({ip})({tags.split(",")}) to {hostname}')
    print(message) 
    slack.chat.post_message('#paloaltonetworks', message, username='@Lab-Firewall')
    

hostname = '192.168.55.10'
username = 'admin'
password = 'paloalto'
ip = ''
selection = ''
# Connect to the device and determine its type (Firewall or Panorama).
device = PanDevice.create_from_device(hostname,
                                        username,
                                        password,
                                        )

        # Panorama does not have a userid API, so exit.
        # You can use the userid API on a firewall with the Panorama 'target'
        # parameter by creating a Panorama object first, then create a
        # Firewall object with the 'panorama' and 'serial' variables populated.
        #3.3.3.1 apache,iis 
        #3.3.3.2 apache
        #3.3.3.3 linux,apache
        #3.3.3.4 windows,iis
        #3.3.3.5 windows
        #3.3.3.6 linux

#ARGS
print("\n"*15)

while selection is not 'q':
    
    print('################################################')
    print('#                                              #')
    print('#    Select one os the follwoing options       #')
    print('#                                              #')    
    print('#    1) Register an IP address/tag             #')
    print('#    2) Unregister an IP address/tag           #')
    print('#    3) Clear All Registrations                #')
    print('#    4) Show All Registrations                 #')
    print('#                                              #')
    print('################################################')
    selection = input('Enter selection: ')
    print("\n"*15)

    if selection is '1':
        ip = input('Enter IP address to register: ')
        tags = input('Enter 1 or more tags(tag1,tag2): ')
        register(ip,tags)
    
    elif selection is '2':
        ip = input('Enter IP address to unregister: ')
        tags = input('Enter 1 or more tags(tag1,tag2): ')
        unregister(ip,tags)
    
    elif selection is '3':
        reg_clear()
    
    elif selection is '4':
        show_list()
        

    
    if issubclass(type(device), Panorama):
        logging.error("Connected to a Panorama, but user-id API is not possible on Panorama.  Exiting.")
        sys.exit(1) 




