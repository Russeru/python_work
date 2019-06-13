#!/usr/bin/python
""" Sanitize Splunk syslog export files for general use.

Removes customer specific strings and IP addresses while retaining important
relationships among the data to allow for sharing and demonstration of the data.

This scripts walk through the file in a single pass, learning what it can from
each line and then updates the line with the learned data.  It is important that
every message that contains data to be sanitized also learns from that line because
we don't know which order we will encounter any particular type of syslog message.

When IPs are learned, they are placed into a dictionary with the key of the original
IP and the value of a new IP address that starts with a fixed value (e.g. 10.10.) and
then each new IP learned gets the next incremental IP (e.g. 10.10.1.54).

There are options to import a comma-separated list of source ips or dest ips from
a file named in command line options

There is also an option to automatically replace the top source or destination ips
specified in a file containing a flat list of ips. This requires another pass.

"""

import sys, os, re
import argparse
import datetime
import calendar
import struct
import array
import operator


class SanitizeClass(object):
    """ Base class for sanitization of each specific type of data in syslog output.

    Each key or type of key in the syslog message will have its own instance
    so that it can be searched for and replaced with its particular data.

    Attributes:
        clean_name: String for the base of the sanitized values for this field.
        type_key: String of the type in the syslog message or 'any' if it applies to all.
        attr_key: String for the attribute key in the syslog message.
        top_key: Optional string for lines that require learning/sanitizing multiple values, like top-srvgrp
    """

    def __init__(self, clean_name, type_key, attr_key, top_key = "none"):
        """ Initializes SanitizeClass with the search and replace attributes."""
        self._clean_name = clean_name
        self._type_key = type_key
        self._attr_key = attr_key
        self._top_key = top_key

        #add our defaults into the dictionary so that we don't change them in the syslog file
        self._insts = {}
        self._num_defaults = 0
        self._insts["default"] = "default"
        self._insts["any"] = "any"
        self._insts["all"] = "all"
        self._num_defaults = len(self._insts)

    def _extract_by_key(self, line, key):
        """ Return the value of a particular key in this message, or notfound."""
        search = r'{0}=.+?,'.format(key)   # lazy match to first ,
        attr_match = re.search(search, line)
        if attr_match:
            # grab just the value of the attribute from attr_key=value,
            value = attr_match.group()[len(key) + 1 : len(attr_match.group()) - 1]
            return value
        else:
            return "notfound"

    def find(self, line):
        """ Finds the specific syslog attribute in the line and returns just the value."""
        return self._extract_by_key(line, self._attr_key)

    def learn(self, line):
        """ Learns the attribute for later substitution, if it is found."""
        value = self.find(line)
        if value is not "notfound" and not value in self._insts:
            self._insts[value] = "%s_%d" % (self._clean_name, len(self._insts) - self._num_defaults + 1)
        #if the line type requires multiple values to be replaced, do that instead of only searching for one
        elif self._top_key != "none":
            top_components = line.split(",")
            for comp in top_components:
                samples = comp.split("=")
                if self._top_key in samples[0]:
                    if samples[1] not in self._insts:
                        self._insts[samples[1]] = "%s_%d" % (self._clean_name, len(self._insts) - self._num_defaults + 1)
                        print self._insts[samples[1]]

    def sanitize(self, line):
        if (self._top_key != "none"):
            components = line.split(",")
            for comp in components:
                items = comp.split("=")
                if self._top_key in items[0]:
                    if items[1] in self._insts:
                        line = line.replace(_wrap_attr(items[1]), _wrap_attr(self._insts[items[1]]))
        """ Find the attribute to change and then change it (but check for message type first)."""
        if self._type_key is 'any' or line.find("type=" + self._type_key) != -1:
            value = self.find(line)
            if value is not "notfound" and value in self._insts:
                new_value = self._insts[value]
                line = line.replace(_wrap_attr(value), _wrap_attr(new_value))
        return line


class SanitizeIPClass(SanitizeClass):
    """ Subclass of SanitizeClass to get special processing for IP Addresses."""
    line_count = 0
    ip_dict = {}
    top_ip = []

    def learn(self, line):
        """ Override base class method to find the value in *ip and top-*ip messages."""
        mytop = "top-" + self._attr_key
        value = self.find(line)
        if value is not "notfound" and not value in self._insts:
            self._learn_one(value)
        elif mytop in line:
            # this is a top-n that we need to learn all of
            top_components = line.split(",")
            for comp in top_components:
                samples = comp.split("=")
                if "ip" in samples[0]:
                    if samples[1] not in self._insts:
                        self._learn_one(samples[1])

    def _learn_one(self, value):
        """ Special IPs learning logic to span the octets as we increment. """
        total_entries = len(self._insts)
        second_octet = (total_entries / 250) + 1
        first_octet =  total_entries - ((second_octet - 1) * 250) + 1
        self._insts[value] = "%s.%d.%d" % (self._clean_name, second_octet, first_octet)

    def load_from_file(self, file):
        """ Load IPs into mapping from file """

        if (args.replacetopip): #create list of IP addresses and the number of times they occur
            with open(args.dirty) as dirty_file:
                for line in dirty_file:
                    ip = self._extract_by_key(line, self._attr_key)
                    if (self.ip_dict.has_key(ip)):
                        self.ip_dict[ip] += 1
                    else:
                        self.ip_dict[ip] = 1
            #sort list
            self.top_ip = sorted(self.ip_dict.items(), key=operator.itemgetter(1), reverse=True)
        count = 0
        with open(file) as ip_file:
            for line in ip_file:
                if (args.replacetopip): #replace top IP addresses from the sorted list with new ones from the file
                    ip_old = self.top_ip[count][0]
                    ip_new = line.strip()
                    count += 1
                else:
                    ip_old,ip_new = line.split(",")
                self._insts[ip_old] = ip_new.strip()

    def _v4_string_to_hex(self, v4_string):
        """ Convert the IPv4 dotted string notation to its hex string."""
        octets = v4_string.split(".")
        return "".join('{:02x}'.format(int(octet)) for octet in octets)

    def find_packet_dimensions(self, pdu):
        if (pdu[24 : 28] == "0800"):
            ip_header_pos = 28
            header_length = str(bin(int(pdu[28:30], 16))[2:].zfill(8))[4:]
            ip_header_end = ip_header_pos + (int(header_length, 2) * 8)
        else:
            print "Encountered unexpected ethertype on line " +  str(self.line_count) + ".\nExpected: 0800 \nActual: " + pdu[24:28]
            return 0,0

        return ip_header_pos, ip_header_end

    def fix_checksum(self, pdu):
        pdu = pdu.rstrip(",\n")
        ip_header_pos, ip_header_end = self.find_packet_dimensions(pdu)
        if (ip_header_pos, ip_header_end == 0,0):
            return pdu
        #get the header for calculating the checksum while also clearing out the old checksum
        data = str(pdu[ip_header_pos : ip_header_pos + 20]) + "0000" + str(pdu[ip_header_pos + 24 : ip_header_end])
        data = " ".join(data[i:i+2] for i in range(0, len(data), 2)) #format it with spaces
        data = data.split()
        #catch an error caused by special characters in the pdu, caused by unintentionally replacing hex with an IP address
        try:
            data = map(lambda x: int(x,16), data)
        except ValueError:
            print "ValueError on line " + str(self.line_count) + '\n'
            print pdu
            return pdu + ",\n"
        data = struct.pack("%dB" % len(data), *data)
        clean_checksum =  ("0x%04x" % checksum(data)) #re-calculate checksum
        clean_checksum = re.sub("0x", "", clean_checksum) #strip away '0x'
        pdu = pdu[0 : ip_header_pos + 20] + clean_checksum + pdu[ip_header_pos + 24:] #replace checksum

        #if it is a TCP or UDP packet, fix those checksums as well
        protocol = pdu[ip_header_pos + 18 : ip_header_pos + 20]
        if (protocol == "06" or protocol == "11"):
            #TCP
            if (protocol == "06"):
                checksum_pos = ip_header_end + 32
                padding_pos = ip_header_end + 40

            #UDP
            elif (protocol == "11"):
                checksum_pos = ip_header_end + 12
                padding_pos = ip_header_end + 32

            #remove padding for packets that have it
            try:
                if (int(pdu[padding_pos: len(pdu)], 16) == 0):
                    pdu = pdu[0:padding_pos]
            except ValueError:
                pass

            #get header while zeroing out checksum, and calculate the header length
            header = pdu[ip_header_end : checksum_pos] + "0000" + pdu[checksum_pos + 4:]
            length = str(hex(len(header)/2)[2:])
            while (len(length) < 4):
                length = "0" + length #pad with zeroes

            #get data needed to calculate checksum, including pseudo-header.
            data = (pdu[ip_header_pos + 24: ip_header_end] + "00" + protocol + length + header)
            #format it so the checksum function works correctly
            data = " ".join(data[i:i+2] for i in range(0, len(data), 2))
            data = data.split()
            data = map(lambda x: int(x,16), data)
            data = struct.pack("%dB" % len(data), *data)

            clean_checksum =  ("0x%04x" % checksum(data)) #re-calculate the checksum
            clean_checksum = re.sub("0x", "", clean_checksum) #strip away '0x'

            pdu = pdu[0 : checksum_pos] + clean_checksum + pdu[checksum_pos + 4:] #replace checksum

        return pdu

    def sanitize(self, line):
        """ Override for IP to split the line up and match anything that has 'ip' in the key.

            Then modify the pdu because it has IPs in it too
        """
        self.line_count = self.line_count + 1
        components = line.split(",")
        for comp in components:
            # if any field has IP in it, see if the value matches something in the dict
            items = comp.split("=")
            if "ip" in items[0]:
                if items[1] in self._insts:
                    # found this dirty IP in our learned dictionary, replace it
                    dirty_ip = items[1]
                    clean_ip = self._insts[dirty_ip]
                    line = re.sub(dirty_ip, clean_ip, line, 1)

                    # if this message has a pdu, clean up the pdu too
                    msg_type = self._extract_by_key(line, "type")
                    if "sflow" in msg_type or "event" in msg_type:
                        pdu = self._extract_by_key(line, "pdu")
                        # substitute the converted IP based on type
                        if "." in dirty_ip:
                            # v4
                            line = re.sub(self._v4_string_to_hex(dirty_ip),
                                      self._v4_string_to_hex(clean_ip), line)

                            pdu = self.fix_checksum(pdu)

                            line = line[0: (line.find("pdu=")) +4] + pdu + ",\n"
                        else:
                            # v6 - remove : and go to lower case before swap
                            dirty_swap = re.sub(":", "", dirty_ip)
                            dirty_swap = dirty_swap.lower()
                            line = re.sub(dirty_swap, self._v4_string_to_hex(clean_ip), line)
                        if (args.hexdump):
                            pdu_hex = pdu
                            pdu_hex = " ".join(pdu_hex[i:i+2] for i in range(0, len(pdu_hex), 2)) #put timestamp and offset in front of pdu hex
                            pdu_hex = pdu[0:15] + " 000000 " + pdu_hex + " ,\n"
                            hexdump_file.write(pdu_hex)
        return line

def _wrap_attr(attr):
    """ Wrap an attribute with an = and , to make search more specific."""
    return '={0},'.format(attr)

def _set_date(line, dirtydate, date):
    """ Set the date on each line.

    This is useful so that we don't have to remember when the data actually was taken.
    If the data spans midnight, start one day earlier (not implemented yet)
    """
    line = re.sub(dirtydate, date, line, 2)
    return line

def _set_time(line, old_time, swap_time):
    """ Set the time on each line

    """
    line = re.sub(str(old_time), str(swap_time), line, 2)
    return line

if struct.pack("H",1) == "\x00\x01": # big endian
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff
else:
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s>>8)&0xff)|s<<8) & 0xffff

if __name__=='__main__':
    argparser = argparse.ArgumentParser(description=
                                        'Sanitize Syslog exported data to remove customer information')

    # Input file
    argparser.add_argument("dirty", help='Unsanitized file to read')
    # Output app file
    argparser.add_argument("clean", help='Clean file to use')
    # Dest IP mapping
    argparser.add_argument("--dests", type=str, help='Destination IP mapping file')
    # Source IP mapping
    argparser.add_argument("--sources", type=str, help='Source IP mapping file')
    # Desired date
    argparser.add_argument("--date", type=str, help='Date in Mon XX format')
    # Desired time shift
    argparser.add_argument("--shift", type=int, help='Minutes you would like to shift the time back from the original time')
    argparser.add_argument('--version', action='version', version='%(prog)s 1.6')
    argparser.add_argument("--hexdump", type=str, help='Destination file for hexdump of pdus')
    argparser.add_argument("--replacetopip", help="Replace top IPs with the IPs from 'dests' or 'sources' file automatically. Warning: Increases runtime.", action = 'store_true')

    args = argparser.parse_args()

    print "Sanitizing " + args.dirty + " and writing to " + args.clean
    if (args.hexdump):
        hexdump_file = open(args.hexdump, 'w')

    #make a dictionary of month strings to their numerical values for later use
    monthToNum = {v: k for k,v in enumerate(calendar.month_abbr)}
    current_year = int(datetime.date.today().strftime("%Y"))

    # create instances of SanitizeClass and put into a list
    # so that we can execute in a loop
    sanitizers = []
    sanitizers.append(SanitizeClass('SG', 'any', 'srvgrp'))
    sanitizers.append(SanitizeClass('SG', 'top-srvgrp', 'srvgrp', 'group'))
    sanitizers.append(SanitizeClass('CL', 'any', 'cl'))
    sanitizers.append(SanitizeClass('PG', 'any', 'pg'))
    sanitizers.append(SanitizeClass('CUST', 'event', 'cust'))

    # only do source ips if something is configured (can be empty)
    if (args.sources):
        s = SanitizeIPClass('10.10', 'any', 'sip')
        s.load_from_file(args.sources)
        sanitizers.append(s)

    # always do destination IPs
    s = SanitizeIPClass('66.203', 'any', 'dip')
    if (args.dests):
        s.load_from_file(args.dests)
    sanitizers.append(s)


    # do everything in a single pass because we learn from every important field
    # so we should be able to write back into the same message with the necessary data
    #        1) extract new dictionary data that can be gleaned per type
    #           (hosts, server groups, protection groups, clusters, etc)
    #        2) set the date to something easy (yesterday) if not configured
    #        3) modify the line based on the learned, sanitized data
    #        4) write the line into the output file

    clean_file = open(args.clean, 'w')
    with open(args.dirty) as dirty_file:

        # prep the date to yesterday unless one is configured
        if (args.date):
            swap_day = args.date
            swap_month_num = monthToNum[args.date[0:3]]
        else:
            swap_day = ((datetime.date.today()) - (datetime.timedelta(days=1))).strftime("%b %d")
        match = re.match(r'[\S]+[\s]+[\d]+', dirty_file.readline())
        dirty_date = match.group()
        dirty_month = monthToNum[dirty_date[0:3]]
        first_day = int(dirty_date[4:6])

        dirty_file.seek(0)       # reset pointer because we just read the first line
        for line in dirty_file:
            # learn what we can before we sanitize
            for s in sanitizers:
                s.learn(line)

            is_reversed = False
            #check if the date is not equal to the date of the first line. if so, assume the data spans midnight
            day = int(line[4:6])
            if (day == first_day):
                spans_midnight = False
            elif (day < first_day):
                spans_midnight = True
            elif (day > first_day):
                spans_midnight = True
                is_reversed = True

            shifting_over_midnight = False
            #shift the time back the desired number of minutes
            if (args.shift):
                #make a datetime object to allow it to correctly calculate the time
                date_time = datetime.datetime(current_year, dirty_month, day, int(line[7:9]), int(line[10:12]), int(line[13:15]))
                swap_time = (date_time - datetime.timedelta(minutes=args.shift))

                #case where the data did not originally span midnight but now does due to shifting
                if (date_time.day != swap_time.day):
                    spans_midnight = True
                    shifting_over_midnight = True

                swap_time = swap_time.time()
                old_time = date_time.time()
                line = _set_time(line, old_time, swap_time)

                #if the data spans midnight, change swap_day by one day to account for this.
            if (spans_midnight):
                if (is_reversed):
                    #also change the dirty_date so that it knows to look for the day before the original date.
                    if (not shifting_over_midnight):
                        dirty_date = (datetime.datetime(current_year, dirty_month, first_day) + datetime.timedelta(days=1)).strftime(("%b %d"))
                    if (args.date):
                        swap_day = (datetime.datetime(current_year, swap_month_num, int(args.date[4:6])) + datetime.timedelta(days=1)).strftime(("%b %d"))
                    else:
                        swap_day = (datetime.date.today()).strftime("%b %d")
                else:
                    if (not shifting_over_midnight):
                        dirty_date = (datetime.datetime(current_year, dirty_month, first_day) - datetime.timedelta(days=1)).strftime(("%b %d"))
                    if (args.date):
                        swap_day = (datetime.datetime(current_year, swap_month_num, int(args.date[4:6])) - (datetime.timedelta(days=1))).strftime(("%b %d"))
                    else:
                        swap_day = ((datetime.date.today()) - (datetime.timedelta(days=2))).strftime("%b %d")

            # set the date to desired date
            line = _set_date(line, dirty_date, swap_day)

            # sanitize all types
            for s in sanitizers:
                line = s.sanitize(line)

            clean_file.write(line)
    if (args.hexdump):
        hexdump_file.close()
    clean_file.close()

