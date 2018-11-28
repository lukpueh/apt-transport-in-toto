#!/usr/bin/env python
"""
<Program Name>
  intoto.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  November 22, 2018.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide an in-toto transport method for apt to perform in-toto
  verification using in-toto link metadata fetched from a rebuilder.

  - This program must be available as executable in
      `/usr/lib/apt/methods/intoto`.
  - The in-toto transport can be used by adding the `intoto` method name to
    URIs in `/etc/apt/sources.list` or `/etc/apt/sources.list.d/*`, e.g.
      `deb intoto://ftp.us.debian.org/debian/ jessie main contrib`
  - The in-toto transport uses the http transport to download the target debian
    packages.
  - Verification is performed on `apt-get install`, i.e. when we receive
    a `600 URI Acquire` message for a debian package.
  - Verification is not performed on `apt-get update`, i.e. when we receive
    a `600 URI Acquire` message with a header field `Index-File: true`.
  - A root layout must be present on the client system, the 
    path may be specified in the method's config file
    `/etc/apt/apt.conf.d/intoto`.
  - Corresponding layout root keys must be present in the client gpg chain
  - The base path of the remote rebuilder that hosts in-toto link metadata may
    be specified in the client method config file.
  - The full path of the in-toto link metadata for a given package is inferred
    from the configured base path and the package URI in `600 URI Acquire`.
  - That information may also be used for in-toto layout parameter
    substitution.


<Resources>
  APT method interface
  http://www.fifi.org/doc/libapt-pkg-doc/method.html/ch2.html

  Apt Configuration
  See https://manpages.debian.org/stretch/apt/apt.conf.5.en.html for syntax

  Apt sources list syntax
  See https://wiki.debian.org/SourcesList


  The flow of messages starts with the method sending out a 100 Capabilities
  and APT sending out a 601 Configuration. After that APT begins sending 600
  URI Acquire and the method sends out 200 URI Start, 201 URI Done or 400 URI
  Failure. No synchronization is performed, it is expected that APT will send
  600 URI Acquire messages at -any- time and that the method should queue the
  messages. This allows methods like http to pipeline requests to the remote
  server. It should be noted however that APT will buffer messages so it is not
  necessary for the method to be constantly ready to receive them.


                    method                      APT
                      +                          +
                      |     100 Capabilities     |
                      | +----------------------> |
                      |                          |
                      |     601 Configuration    |
                      | <----------------------+ |
                      |                          |
                      |      600 URI Acquire     |
                      | <----------------------+ |
                      |                          |
                      |      200 URI Start       |
                      | +----------------------> |
            Download  |                          |
            and write |                          |
            to file   |       201 URI Done       |
                      | +----------------------> |


"""
import os
import sys
import time
import threading
import Queue
import logging
import logging.handlers
import subprocess32 as subprocess

# TODO: Should we setup a SysLogHandler and write to /var/log/apt/intoto ?
LOG_FILE = "/tmp/intoto.log"
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.handlers.RotatingFileHandler(LOG_FILE))


APT_METHOD_HTTP = os.path.join(os.path.dirname(sys.argv[0]), "http")

# APT Method Interface Message definition
# The first line of each message is called the message header. The first 3
# digits (called the Status Code) have the usual meaning found in the http
# protocol. 1xx is informational, 2xx is successful and 4xx is failure. The 6xx
# series is used to specify things sent to the method. After the status code is
# an informational string provided for visual debugging
# Only the 6xx series of status codes is sent TO the method. Furthermore the
# method may not emit status codes in the 6xx range. The Codes 402 and 403
# require that the method continue reading all other 6xx codes until the proper
# 602/603 code is received. This means the method must be capable of handling
# an unlimited number of 600 messages.

# Message types by their status code. Each message type has an "info" and
# and the a list of allowed fields. APT_MESSAGE_TYPES may be used to verify
# the format of the received messages.
APT_MESSAGE_TYPES = {
  # Method capabilities
  100: {
    "info": "Capabilities",
    "fields": ["Version", "Single-Instance", "Pre-Scan", "Pipeline",
        "Send-Config", "Needs-Cleanup"]
  },
  # General Logging
  101: {
    "info": "Log",
    "fields": ["Message"]
  },
  # Inter-URI status reporting (login progress)
  102: {
    "info": "Status",
    "fields": ["Message"]
  },
  # URI is starting acquire
  200: {
    "info": "URI Start",
    "fields": ["URI", "Size", "Last-Modified", "Resume-Point"]
  },
  # URI is finished acquire
  201: {
    "info": "URI Done",
    "fields": ["URI", "Size", "Last-Modified", "Filename", "MD5-Hash",
      # NOTE: Although not documented we need to include all these hash algos
      # https://www.lucidchart.com/techblog/2016/06/13/apt-transport-for-s3/
      "MD5Sum-Hash", "SHA1-Hash", "SHA256-Hash", "SHA512-Hash"]
  },
  # URI has failed to acquire
  400: {
    "info": "URI Failure",
    "fields": ["URI", "Message"]
  },
  # Method did not like something sent to it
  401: {
    "info": "General Failure",
    "fields": ["Message"]
  },
  # Method requires authorization to access the URI. Authorization is User/Pass
  402: {
    "info": "Authorization Required",
    "fields": ["Site"]
  },
  # Method requires a media change
  403: {
    "info": "Media Failure",
    "fields": ["Media", "Drive"]
  },
  # Request a URI be acquired
  600: {
    "info": "URI Acquire",
    "fields": ["URI", "Filename", "Last-Modified"]
  },
  # Sends the configuration space
  601: {
    "info": "Configuration",
    "fields": ["Config-Item"]
  },
  # Response to the 402 message
  602: {
    "info": "Authorization Credentials",
    "fields": ["Site", "User", "Password"]
  },
  # Response to the 403 message
  603: {
    "info": "Media Changed",
    "fields": ["Media", "Fail"]
  }
}


def deserialize_one(message_str):
  """Parse raw message string as it may be read from stdin and return a
  dictionary that contains message header status code and info and an optional
  fields dictionary of additional headers and their values.

  Raise Exception if the message is malformed. See APT_MESSAGE_TYPES for
  details about formats.
  NOTE: We are pretty strict about the format of messages that we receive.
  Given the vagueness of the specification, we might be too strict.

  {
    "code": <status code>,
    "info": "<status info>",
    "fields": [
      ("<header field name>", "<value>"),
    ]
  }

  NOTE: Message field values are NOT deserialized here, e.g. the Last-Modified
  time stamp remains a string and Config-Item remains a string of item=value
  pairs.

  """
  lines = message_str.splitlines()
  if not lines:
    raise Exception("Invalid empty message: {}".format(message_str))

  # Deserialize message header
  message_header = lines.pop(0)
  message_header_parts = message_header.split()

  # TODO: Are we too strict about the format (should we not care about info?)
  if len(message_header_parts) < 2:
    raise Exception("Invalid message header: {}".format(message_header))

  code = int(message_header_parts.pop(0))
  if code not in APT_MESSAGE_TYPES.keys():
    raise Exception("Invalid message header status code: {}".format(code))

  # TODO: Are we too strict about the format (should we not care about info?)
  info = " ".join(message_header_parts).strip()
  if info != APT_MESSAGE_TYPES[code]["info"]:
    raise Exception("Invalid message header info for status code {}: {}"
        .format(code, info))

  # Deserialize header fields
  header_fields = []
  for line in lines:
    # FIXME: Should we be assert (above) that the last line is a blank line?
    if line == "\n":
      continue

    header_field_parts = line.split(":")

    if len(header_field_parts) < 2:
      raise Exception("Invalid header field: {}".format(line))

    field_name = header_field_parts.pop(0).strip()

    if field_name not in APT_MESSAGE_TYPES[code]["fields"]:
      logger.warning("Unsupported header field for message code {}: {}"
          .format(code, field_name))

    field_value = ":".join(header_field_parts).strip()
    header_fields.append((field_name, field_value))

  # Construct message data
  message_data = {
    "code": code,
    "info": info
  }
  if header_fields:
    message_data["fields"] = header_fields

  return message_data


def serialize_one(message_data):
  """Create a message string that may be written to stdout. Message data
  is expected to have the following format:
  {
    "code": <status code>,
    "info": "<status info>",
    "fields": [
      ("<header field name>", "<value>"),
    ]
  }

  """
  message_str = ""

  # Code must be present
  code = message_data["code"]
  # Convenience (if info not present, info for code is used )
  info = message_data.get("info") or APT_MESSAGE_TYPES[code]["info"]

  # Add message header
  message_str += "{} {}\n".format(code, info)

  # Add message header fields and values (must be list of tuples)
  for field_name, field_value in message_data.get("fields", []):
    for val in field_value:
      message_str += "{}: {}\n".format(field_name, val)

  # Blank line to mark end of message
  message_str += "\n"

  return message_str



def read_one(stream):
  message_str = ""
  while True:
    # Read from stdin line by line (does not strip newline character)
    # NOTE: This may block forever
    line = stream.readline()
    if line:
      message_str += line

    # Blank line denotes message end (EOM)
    # Empty line denotes end of file (EOF)
    if not line or line == "\n":
      break

  if message_str:
    return message_str

  return None


def write_one(message_str, stream):
  stream.write(message_str)
  stream.flush()

"""
two queues
 - apt_message_queue
 - http_message_queue

two locks
 - apt_message_lock
 - http_message_lock

two threads
 - read_on(http_proc.stdout)
 - read_on(sys.stdin)

 write to corresponding queue using corresponding lock

in main thread

alternting pop from queues using locks and write to corresponding out stream

"""
def read_to_queue(stream, queue):
  # This blocks until a message is availabe
  while True:
    msg = read_one(stream)
    if msg:
      queue.put(msg)
      return





def loop():
  """Main in-toto http loop to relay messages betwen apt and the http
  transport method.  If apt sends a `600 URI Acquire message`, for a debian
  package we perform in-toto verification and only relay the message if
  verification is successful.
  """
  # Start http transport in a subprocess
  # It will do all the regular http transport work for us and send messages to
  # the inherited `stdout`, i.e. the one that apt reads from.
  # Messages from apt (`stdin`) are intercepted below and only forwarded once
  # we have done our in-toto verification work
  # http_proc = subprocess.Popen([APT_METHOD_HTTP], stdin=subprocess.PIPE,
  #     stdout=subprocess.PIPE)


  http_proc = subprocess.Popen([APT_METHOD_HTTP], stdin=subprocess.PIPE,
      stdout=subprocess.PIPE)


  http_queue = Queue.Queue()
  http_thread = threading.Thread(target=read_to_queue, args=(http_proc.stdout, http_queue,))
  http_thread.start()

  apt_queue = Queue.Queue()
  apt_thread = threading.Thread(target=read_to_queue, args=(sys.stdin, apt_queue,))
  apt_thread.start()


  while True:
    # reading message
    for message_queue, output_stream in \
        [(http_queue, sys.stdout), (apt_queue, http_proc.stdin)]:

      logger.info("reading queue")
      msg = message_queue.get()
      logger.info("read queue")
      if msg:
        write_one(msg, output_stream)

      time.sleep(0.1)


  # Loop while we get messages from apt (sys.stdin) or http (proc.stdout)
  # while True:
  #   message_apt = read_one(stream=sys.stdin)
  #   message_http = read_one(stream=proc.stdout)

  #   # No more messages, we are done here
  #   if not message_apt or message_http:
  #     return None

  #   # Relay apt message to http
  #   if message_apt:
  #     write_one(message_apt + "\n", proc.stdin)

  #   # Relay http message to apt
  #   if message_http:
  #     write_one(message_http + "\n", sys.stdout)

    # # Deserialize the message and see if it is relevant for us
    # message_data = deserialize_one(message)
    # if message_data.get("code") == 600:

    #   # not_an_index_file = (not msg_fields.get("Index-File") or
    #   #     msg_fields.get("Index-File") == "no")
    #   # uri = msg_fields.get("URI")

    #   # # We only do in-toto verification if it is 
    #   # if uri and not_an_index_file:
    #   logger.info("Starting in-toto verification for '{}'".format("uri"))
    #   # TODO:
    #   # While sending 100/101 logging or status messages:
    #   # Parse in-toto apt method configuration (link location, layout, keys)
    #   # Download links (to tempdir)
    #   # Run in-toto-verify
    #   # Should we abort and send a failure if verification fails?
    #   logger.info("Finished in-toto verification for '{}'".format("uri"))

    # # Relay raw message to http transport
    # write_one(message + "\n", stream=proc.stdin)


if __name__ == "__main__":
  loop()
