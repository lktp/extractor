#!/usr/bin/python

###############################################################################
#
#                       name: pcap_extractor.py
#                       author: Adam LeTang (Sherpa)
#                       Creation date: 19 May 2018
#                       purpose: TO autmatically extract files from pcap
#                       TODO: put more analysis into this so it can try to figure out if the file is somewhere
#                       Bugs: None at this time
#                       Dependiences: Scappy
#
#
#
#
################################################################################

#imports needed, (binascii to play with hex, and scappy to play with the packets
from scapy.all import *
from binascii import unhexlify, hexlify 
import sys
#This functions who purpose in ife is to figure out what the extenision of the file is.  right now it pretty much
#has to be hard coded in...I wanna find another way to do that, Just havent gotten around to it yet.
def get_extensions(header):
   headers = [{'HEADER': 'd0cf', 'EXTENSION': 'doc'},
              {'HEADER': '4d5a', 'EXTENSION': 'exe'},
              {'HEADER': '504b0304', 'EXTENSION': 'zip'},
              {'HEADER': '504b0506', 'EXTENSION': 'zip'}]
   for i in headers:
      if str(header).strip() == str(i['HEADER']).strip():
         return i['EXTENSION']
   return "unkown"

#This will create the sessions.  It creates the sessions by searching for any packet that has the same IPs, and PORTS.
def parse_pcap(packet_list):
   #List of sessions
   sessions = []  
   #walks through the packets from the pcap
   for i in packet_list:  
      #checks to see if there are any sessions, then creates one                        
      if not sessions: 
         #creates the packet list, to push into the packet dictionary.
         packets = [] 
         packets.append(i) 
         # a dictionary of session metadata
         packet = {'IP1': i['IP'].src, 'IP2': i['IP'].dst, 'PORT1' : i['TCP'].sport, 'PORT2': i['TCP'].dport, 'PACKETS': packets, 'CONVO_SIZE': i['IP'].len} 
         #list of packet dictionaries
         sessions.append(packet) 
         continue 
      else:
         found = False
         #checks all sessions for matches
         for session in sessions:   
            #matches if both IPs and both ports are in the packets
            if i['IP'].src in session.values() and i['IP'].dst in session.values() and i['TCP'].sport in session.values() and i['TCP'].dport in session.values():
               session['PACKETS'].append(i)
      	       session['CONVO_SIZE'] = session['CONVO_SIZE'] + i['IP'].len
               found = True
         #if not a match, it creates a new session.
         if not found:
            packets = []
            packets.append(i) 
            packet = {'IP1': i['IP'].src, 'IP2': i['IP'].dst, 'PORT1' : i['TCP'].sport, 'PORT2': i['TCP'].dport, 'PACKETS': packets, 'CONVO_SIZE': i['IP'].len}
            sessions.append(packet)
   return sessions

def parse_sessions(sessions):
   count = 1
   for i in sessions:
      ip1_len = 0
      ip2_len = 0
      ip1_session = ''
      ip2_session = ''
      for j in i['PACKETS']:
         #finds the length of one side of the session
         if j['IP'].src == i['IP1']:
            ip1_len += j['IP'].len
            try:
               #saves the hex for pushing into a file
               ip1_session +=  unhexlify(j['TCP'].load).encode('hex_codec')
            except:
               continue
         #finds the length of the other side of the session
         elif j['IP'].src == i['IP2']:
            ip2_len += j['IP'].len
            try:
               #saves hex for pushing into file.
               ip2_session += unhexlify(j['TCP'].load.encode('hex_codec'))
            except:
               continue

      #this if...elif...else state ment is for trying to figure out what side the session transfered files..  It is based soley on size. Once it finds that it will attempt to
      #write the file to disk, then transfer the process over to the get_extensions function.
      #should try testing this with text files, right now ive only done it with binary.
      if ip1_len > ip2_len:
         header = hexlify(ip1_session[:2])
         extension = get_extensions(header)
         print "%s seems to be the one with the transfer" %i['IP1']
         file = open('file%s.%s' % (count, extension), 'wb')
         file.write(ip1_session)
         file.close()
         print " Your file was saved as 'test%s.%s'.\n If it has an extension of unkown, add the file header and document type to the get_extensions function." % (count, extension)
      elif ip1_len < ip2_len:
         header = hexlify(ip2_session[:2])
         extension = get_extensions(header)
         file = open('file%s.%s' % (count, extension), 'wb')
         print "%s seems to be the one with the transfer" %i['IP2']
         file.write(ip2_session)
         file.close()
         print " Your file was saved as 'test%s.%s'.\n If it has an extension of unkown, add the file header and document type to the get_extensions function." % (count, extension)
      else:
         print 'I dont fucking know'
      count +=1

#Control function, dosent do much besides asking a user what session they want to try...should probably put that in a while loop.
if __name__ == '__main__':
   if len(sys.argv) < 2:
      print "usage: extractor <pcap_file>"
      sys.exit()
   pcap_file = sys.argv[1]
   test = rdpcap(pcap_file)
   sessions = parse_pcap(test)
   count = 1
   for i in sessions:
      print "session number %s" %count
      print "Session size %s" %i['CONVO_SIZE']
      print "Partners %s, %s" %(i['IP1'], i['IP2'])
      count +=1
   input = raw_input("what session do you wanna try to parse?\n>>")   
   if input.lower() == "all":
      parse_sessions(sessions)
   else:
      small_list = []
      small_list.append(sessions[int(input) -1])
      parse_sessions(small_list)     
