# file eulfedora/util.py
# 
#   Copyright 2010,2011 Emory University Libraries
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from contextlib import contextmanager
from datetime import datetime
from dateutil.tz import tzutc
import httplib
import logging
import mimetypes
import random
import re
import requests
import string
import threading
import time
import urllib
from cStringIO import StringIO

from base64 import b64encode
from urlparse import urljoin, urlsplit

from rdflib import URIRef, Graph

from eulxml import xmlmap

from poster import streaminghttp

logger = logging.getLogger(__name__)

# utilities for making HTTP requests to fedora

def auth_headers(username, password):
    "Build HTTP basic authentication headers"
    if username and password:
        token = b64encode('%s:%s' % (username, password))
        return { 'Authorization': 'Basic ' + token }
    else:
        return {}

class RequestFailed(IOError):
    '''An exception representing an arbitrary error while trying to access a
    Fedora object or datastream.
    '''
    error_regex = re.compile('<pre>.*\n(.*)\n', re.MULTILINE)
    def __init__(self, response):
        # init params:
        #  response = HttpResponse with the error information
        super(RequestFailed, self).__init__('%d %s' % (response.status_code, response.error))
        self.code = response.status_code
        self.reason = response.error
        if response.status_code == requests.codes.server_error:
            # when Fedora gives a 500 error, it includes a stack-trace - pulling first line as detail
            # NOTE: this is likely to break if and when Fedora error responses change
            if response.headers['content-type'] == 'text/plain':
                # for plain text, first line of stack-trace is first line of text
                self.detail = response.content.split('\n')[0]
            else:
                # for html, stack trace is wrapped with a <pre> tag; using regex to grab first line
                match = self.error_regex.findall(response.content)
                if len(match):
                    self.detail = match[0]

                    

class PermissionDenied(RequestFailed):
    '''An exception representing a permission error while trying to access a
    Fedora object or datastream.
    '''

class ChecksumMismatch(RequestFailed):
    '''Custom exception for a Checksum Mismatch error while trying to
    add or update a datastream on a Fedora object.
    '''
    error_label = 'Checksum Mismatch'
    def __init__(self, response):
        super(ChecksumMismatch, self).__init__(response)
        # the detail pulled out by  RequestFailed.__init__ includes extraneous
        # Fedora output; when possible, pull out just the checksum error details.
        # The error message will look something like this:
        #    javax.ws.rs.WebApplicationException: org.fcrepo.server.errors.ValidationException: Checksum Mismatch: f123b33254a1979638c23859aa364fa7
        # Use find/substring to pull out the checksum mismatch information
        if self.error_label in self.detail:
            self.detail = self.detail[self.detail.find(self.error_label):]
 
    def __str__(self):
        return self.detail


# custom exceptions?  fedora errors:
# fedora.server.errors.ObjectValidityException
# ObjectExistsException

def parse_rdf(data, url, format=None):
    fobj = StringIO(str(data)) # rdflib errors on handle unicode here (?!?)
    id = URIRef(url)
    graph = Graph(identifier=id)
    if format is None:
        graph.parse(fobj)
    else:
        graph.parse(fobj, format=format)
    return graph

def parse_xml_object(cls, data, url):
    doc = xmlmap.parseString(data, url)
    return cls(doc)

def datetime_to_fedoratime(datetime):
    # format a date-time in a format fedora can handle
    # make sure time is in UTC, since the only time-zone notation Fedora seems able to handle is 'Z'
    utctime = datetime.astimezone(tzutc())      
    return utctime.strftime('%Y-%m-%dT%H:%M:%S') + '.%03d' % (utctime.microsecond/1000) + 'Z'


def fedoratime_to_datetime(rep):
    if rep.endswith('Z'):       
        rep = rep[:-1]      # strip Z for parsing
        tz = tzutc()
        # strptime creates a timezone-naive datetime
        dt = datetime.strptime(rep, '%Y-%m-%dT%H:%M:%S.%f')
        # use the generated time to create a timezone-aware
        return datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond, tz)
    else:
        raise Exception("Cannot parse '%s' as a Fedora datetime" % rep)
