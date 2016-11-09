
import stem, stem.connection, stem.socket
from stem.control import EventType, Controller

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import json

import errno # https://stackoverflow.com/questions/14425401/
from socket import error as socket_error

import socket, functools, re, sys
from threading import Thread

import time, datetime

rpc_connection = None

# start of application
def main():

  global rpc_connection

  print 'Opening log file, further output will be there.'

  # redirect output to file, https://stackoverflow.com/questions/7152762
  f = file('OnioNS-Namecoin-stem.log', 'w')
  sys.stdout = f

  # rpc_user and rpc_password are set in the namecoin.conf file
  # TODO: read the login data from config file
  # TODO: read the IP/port from config file
  rpc_user = "user"
  rpc_password = "pass"
  rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8336"%(rpc_user, rpc_password))

  # get current time of day
  now = datetime.datetime.now()

  try:
    # open main controller
    controller = Controller.from_port(port = 9151)
  except stem.SocketError:
    sys.exit("[err] The Tor Browser is not running. Cannot continue")

  controller.authenticate()

  if controller.get_conf('__LeaveStreamsUnattached') != '1':
    sys.exit('[err] torrc is unsafe for name lookups.  Try adding the line "__LeaveStreamsUnattached 1" to torrc-defaults')

  print '[%d:%d | notice] Successfully connected to the Tor Browser.' % (now.minute, now.second)
  sys.stdout.flush()

  event_handler = functools.partial(handle_event, controller)
  controller.add_event_listener(event_handler, EventType.STREAM)

  print '[%d:%d | debug ] Now monitoring stream connections.' % (now.minute, now.second)
  sys.stdout.flush()

  try:
    # Sleeping for 365 days, as upstream OnioNS does, appears to be incompatible with Windows.
    # Therefore, we instead sleep for 1 day inside an infinite loop.
    while True:
      time.sleep(60 * 60 * 24 * 1) #basically, wait indefinitely
  except KeyboardInterrupt:
    print ''



# handle a stream event
def handle_event(controller, stream):
  # Not all stream events need to be attached.
  # TODO: check with Tor Project whether NEW and NEWRESOLVE are the correct list.
  if stream.status not in [stem.StreamStatus.NEW, stem.StreamStatus.NEWRESOLVE]:
    return

  p = re.compile('.*\.bit$', re.IGNORECASE) #maybe it should match .tor in the future and call a different function
  if p.match(stream.target_address) is not None: # if .bit, send to Namecoin
    t = Thread(target=resolveNamecoin, args=[controller, stream])
    t.start()
  elif stream.circ_id is None: # if not .bit and unattached, attach now
    attachStream(controller, stream)

  # print '[debug] Finished handling stream.'



# resolve via Namecoin a stream's destination
def resolveNamecoin(controller, stream):
  now = datetime.datetime.now()

  print '[%d:%d | notice] Detected Namecoin domain!' % (now.minute, now.second)
  sys.stdout.flush()

  dest = None

  # send to Namecoin and wait for resolution

  try:
    # TODO: use ncdns rather than namecoind
    name = "d/" + stream.target_address[:-4]
    name_data = rpc_connection.name_show(name)
    name_value = name_data["value"]
    name_value_parsed = json.loads(name_value)
    name_tor = name_value_parsed["tor"]
    name_ip4 = name_value_parsed["ip"]
    name_ip6 = name_value_parsed["ip6"]
    name_alias = name_value_parsed["alias"]

    # Don't do load balancing due to uncertain fingerprinting risk, only choose first Tor/IPv6/IPv4 address
    if len(name_tor) > 0:
      dest = name_tor[0]
    elif len(name_ip6) > 0:
      dest = name_ip6[0]
    elif len(name_ip4) > 0:
      dest = name_ip4[0]
    # Alias doesn't return a list, it returns a single string that ends with a period (or None if no alias exists).
    elif name_alias is not None:
      dest = name_alias[:-1]

  except JSONRPCException as err:
    now = datetime.datetime.now()
    print '[%d:%d | warn  ] Namecoin client JSON-RPC exception:' % (now.minute, now.second), err
  except ValueError as err:
    now = datetime.datetime.now()
    print '[%d:%d | warn  ] Namecoin value failed to parse as JSON:' % (now.minute, now.second), err
  except KeyError as err:
    now = datetime.datetime.now()
    print '[%d:%d | warn  ] Namecoin value missing an expected field:' % (now.minute, now.second), err
  except Exception as err:
    now = datetime.datetime.now()
    print '[%d:%d | warn  ] Namecoin unexpected error:' % (now.minute, now.second), err

  if dest is None:
    sys.stdout.flush()

    # "If the lookup operation fails, you call 'CLOSESTREAM (stream ID) 2'.  (The 2 means 'resolve failed'." -- Nick Mathewson (tor-dev mailing list, August 2, 2016)
    try:
      controller.close_stream(stream.id, stem.RelayEndReason.RESOLVEFAILED)
    except stem.UnsatisfiableRequest:
      pass

    return

  r=str(controller.msg('REDIRECTSTREAM ' + stream.id + ' ' + dest))
  print '[notice] Rewrote ' + stream.target_address + ' to ' + dest + ', ' + r
  sys.stdout.flush()

  attachStream(controller, stream)



# attach the stream to some circuit
def attachStream(controller, stream):
# print '[debug] Attaching request for ' + stream.target_address + ' to circuit'

  try:
    controller.attach_stream(stream.id, 0)
  except stem.UnsatisfiableRequest:
    pass

  sys.stdout.flush()


if __name__ == '__main__':
  main()
