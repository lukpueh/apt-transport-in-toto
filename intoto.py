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
  Provide an in-toto enabled transport method for apt that downloads a debian
  package and in-toto link metadata generated on a rebuilder.

  The transport communicates with apt over the APT method interface
  See http://www.fifi.org/doc/libapt-pkg-doc/method.html/ch2.html

  This program must be available as executable in
    /usr/lib/apt/methods/intoto

  Configuration can be provided in:
    /etc/apt/apt.conf.d/intoto
  See https://manpages.debian.org/stretch/apt/apt.conf.5.en.html for syntax

  Path style for sources is:
    deb intoto://<???> jessie main contrib
  See https://wiki.debian.org/SourcesList for sources syntax


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



<TODO>
  What is downloaded where?
    - link files will are available on rebuilder, e.g.
      reproducible-builds.engineering.nyu.edu
    - should we configure that url in sources or in /etc/apt/apt.conf.d/intoto?
    - where does the layout come from?
    - where do the layout keys come from?
    - where does the actual debian package come from?

  Do we download with http or https?

"""

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


def deserialize_apt_message(message_str):
  """Parse raw message string as it may be read from stdin and return a
  dictionary that contains message header status code and info and an optional
  fields dictionary of additional headers and their values.

  Raise Exception if the message is malformed. See APT_MESSAGE_TYPES for
  details about formats.
  NOTE: We are pretty strict about the format of messages that we receive.
  Given the vagueness of the specification, we might be too strict.
  FIXME: First communication tests on debian show that we are too strict.
  They send definitely send stuff that's not defined

  {
    "code": <status code>,
    "info": "<status info>",
    "fields" {
      "<header field name>": "<value>",
      ...
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
  # FIXME: Can't use dict. Header field names of a message are not unique!!
  header_fields = {}
  for line in lines:
    header_field_parts = line.split(":")

    if len(header_field_parts) < 2:
      raise Exception("Invalid header field: {}".format(line))

    field_name = header_field_parts.pop(0).strip()

    if field_name not in APT_MESSAGE_TYPES[code]["fields"]:
      raise Exception("Unsupported header field for message code {}: {}"
          .format(code, field_name))

    field_value = " ".join(header_field_parts).strip()
    header_fields[field_name] = field_value

  # Construct message data
  message_data = {
    "code": code,
    "info": info
  }
  if header_fields:
    message_data["fields"] = header_fields

  return message_data


def serialize_apt_message(message_data):
  """Create a message string that may be written to stdout. Message data
  is expected to have the following format:
  {
    "code": <status code>,
    "info": "<status info>",
    "fields" {
      "<header field name>": "<value>",
      ...
  }

  NOTE: We write whatever we get, without checking the format (see
  APT_MESSAGE_TYPES). So it is up to the caller to pass well-formed data and
  also up to apt to tell us if we sent something bad.

  """
  message_str = ""
  # Message header
  message_str += "{} {}\n".format(message_data["code"],
      message_data["info"])

  # Message header fields and values
  for key, val in message_data["fields"].iteritems():
    message_str += "{}: {}\n".format(key, val)

  # Blank line mark end of message
  message_str += "\n"

  return message_str



def transport():
  """Loop to read messages from stdin, write messages to stdout, download
  buildinfo, run in-toto and report back to apt until done. """
  pass



if __name__ == "__main__":
  transport()
