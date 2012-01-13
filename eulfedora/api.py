# file eulfedora/api.py
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

import csv
import logging
from os import path
import urllib
from urlparse import urljoin, urlsplit
import time
import warnings

from soaplib.serializers import primitive as soap_types
from soaplib.serializers.clazz import ClassSerializer
from soaplib.service import soapmethod
from soaplib.client import ServiceClient, SimpleSoapClient
from soaplib.wsgi_soap import SimpleWSGISoapApp

from poster.encode import multipart_encode, MultipartParam
import requests
from StringIO import StringIO

from eulfedora.util import auth_headers, datetime_to_fedoratime, \
     RequestFailed, parse_rdf, PermissionDenied, ChecksumMismatch, RequestFailed

logger = logging.getLogger(__name__)

# low-level wrappers

def _safe_urlencode(query, doseq=0):
    # utf-8 encode unicode values before passing them to urlencode.
    # urllib.urlencode just passes its keys and values directly to str(),
    # which raises exceptions on non-ascii values. this function exposes the
    # same interface as urllib.urlencode, encoding unicode values in utf-8
    # before passing them to urlencode
    wrapped = [(_safe_str(k), _safe_str(v))
               for k, v in _get_items(query, doseq)]
    return urllib.urlencode(wrapped, doseq)

def _safe_str(s):
    # helper for _safe_urlencode: utf-8 encode unicode strings, convert
    # non-strings to strings, and leave plain strings untouched.
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)

def _get_items(query, doseq):
    # helper for _safe_urlencode: emulate urllib.urlencode "doseq" logic
    if hasattr(query, 'items'):
        query = query.items()
    for k, v in query:
        if isinstance(v, basestring):
            yield k, v
        elif doseq and iter(v): # if it's iterable
            for e in v:
                yield k, e
        else:
            yield k, str(v)


class HTTP_API_Base(object):
    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.extra_request_args = {
            'verify': True  # verify SSL certs by default
            # TODO: custom user agent to identify eulfedora/version ? 
        }
        if self.username is not None:
            # store basic auth option to pass when making requests
            self.extra_request_args['auth'] = (self.username, self.password)

    def absurl(self, rel_url):
        return urljoin(self.base_url, rel_url)

    def _sanitize_url(self, url):
        # a unicode url will surprisingly make httplib.Connection raise an
        # exception later if it tries to send a body that includes non-ascii
        # characters. coerce the url into ascii so that doesn't happen
        if isinstance(url, unicode):
            url = url.encode('utf-8')
        if not isinstance(url, basestring):
            url = str(url)
        # list derived from rfc 3987 "reserved" ebnf, plus "%" because we
        # fail without that.
        return urllib.quote(url, safe=":/?[]@!$&'()*+,;=%")

    def prep_url(self, url):
        return self._sanitize_url(self.absurl(url))

    # thinnest possible wrappers around requests calls
    # - add auth, make urls absolute

    def _make_request(self, reqmeth, url, *args, **kwargs):
        kwargs.update(self.extra_request_args)
        response = reqmeth(self.prep_url(url), *args, **kwargs)

        # FIXME: handle 3xx (?) [possibly handled for us by requests]
        if response.status_code >= requests.codes.bad:  # 400 or worse
            # separate out 401 and 403 (permission errors) to enable
            # special handling in client code.
            if response.status_code in (requests.codes.unauthorized,
                                        requests.codes.forbidden):
                raise PermissionDenied(response)
            elif response.status_code == requests.codes.server_error:
                # check response content to determine if this is a
                # ChecksumMismatch or a more generic error
                if 'ValidationException: Checksum Mismatch' in response.content:
                    raise ChecksumMismatch(response)
                else:
                    raise RequestFailed(response)
            else:
                raise RequestFailed(response)

        return response

    def get(self, *args, **kwargs):
        return self._make_request(requests.get, *args, **kwargs)
    
    def put(self, *args, **kwargs):
    	return self._make_request(requests.put, *args, **kwargs)
        
    def post(self, *args, **kwargs):
        return self._make_request(requests.post, *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(requests.delete, *args, **kwargs)

    # also available: head, patch
    

class REST_API(HTTP_API_Base):
    """
       Python object for accessing `Fedora's REST API <http://fedora-commons.org/confluence/display/FCR30/REST+API>`_.
    """

    # always return xml response instead of html version
    format_xml = { 'format' : 'xml'}

    ### API-A methods (access) #### 
    # describeRepository not implemented in REST, use API-A-LITE version

    def findObjects(self, query=None, terms=None, pid=True, chunksize=None, session_token=None):
        """
        Wrapper function for `Fedora REST API findObjects <http://fedora-commons.org/confluence/display/FCR30/REST+API#RESTAPI-findObjects>`_
        and `Fedora REST API resumeFindObjects <http://fedora-commons.org/confluence/display/FCR30/REST+API#RESTAPI-resumeFindObjects>`_

        One and only one of query or terms must be specified.

        :param query: string of fields and terms to search for
        :param terms: phrase search across all fields
        :param pid: include pid in search results
        :param chunksize: number of objects to return at a time
        :param session_token: get an additional chunk of results from a prior search
        :param parse: optional data parser function; defaults to returning
                      raw string data
        :rtype: string
        """
        if query is not None and terms is not None:
            raise Exception("Cannot findObject with both query ('%s') and terms ('%s')" % (query, terms))
        
        http_args = {'resultFormat': 'xml'}
        if query is not None:
            http_args['query'] = query
        if terms is not None:
            http_args['terms'] = terms

        if pid:
            http_args['pid'] = 'true'
        if session_token:
            http_args['sessionToken'] = session_token
        if chunksize:
            http_args['maxResults'] = chunksize

        r = self.get('objects?', params=http_args)
        return r.content, r.url

    def getDatastreamDissemination(self, pid, dsID, asOfDateTime=None, return_http_response=False):
        """Get a single datastream on a Fedora object; optionally, get the version
        as of a particular date time.

        :param pid: object pid
        :param dsID: datastream id
        :param asOfDateTime: optional datetime; ``must`` be a non-naive datetime
            so it can be converted to a date-time format Fedora can understand

        :param return_http_response: optional parameter; if True, the
           actual :class:`httlib.HttpResponse` instance generated by
           the request will be returned, instead of just the contents
           (e.g., if you want to deal with large datastreams in
           chunks).  Defaults to False.
        """
        # TODO: Note that this loads the entire datastream content into
        # memory as a Python string. This will suck for very large
        # datastreams. Eventually we need to either modify this function or
        # else add another to return self.open(), allowing users to stream
        # the result in a with block.

        # /objects/{pid}/datastreams/{dsID}/content ? [asOfDateTime] [download]
        http_args = {}
        if asOfDateTime:
            http_args['asOfDateTime'] = datetime_to_fedoratime(asOfDateTime)
        #url = 'objects/%s/datastreams/%s/content?%s' % (pid, dsID, _safe_urlencode(http_args))
        url = 'objects/%s/datastreams/%s/content' % (pid, dsID)
        r = self.get(url, params=http_args)
        if return_http_response:
            return r
        return r.content, r.url

    # NOTE: getDissemination was not available in REST API until Fedora 3.3
    def getDissemination(self, pid, sdefPid, method, method_params={}, return_http_response=False):        
        # /objects/{pid}/methods/{sdefPid}/{method} ? [method parameters]        
        uri = 'objects/%s/methods/%s/%s' % (pid, sdefPid, method)
        # if method_params:
        #     uri += '?' + _safe_urlencode(method_params)
        r = self.get(uri, params=method_params)
        if return_http_response:
            return r
        else:
            return r.content, r.url

    def getObjectHistory(self, pid):
        # /objects/{pid}/versions ? [format]
        url = 'objects/%s/versions' % (pid, )
        r = self.get(url, params=self.format_xml)
        return r.content, r.url

    def getObjectProfile(self, pid, asOfDateTime=None):
        """Get top-level information aboug a single Fedora object; optionally,
        retrieve information as of a particular date-time.

        :param pid: object pid
        :param asOfDateTime: optional datetime; ``must`` be a non-naive datetime
        so it can be converted to a date-time format Fedora can understand
        """
        # /objects/{pid} ? [format] [asOfDateTime]
        http_args = {}
        if asOfDateTime:
            http_args['asOfDateTime'] = datetime_to_fedoratime(asOfDateTime)
        http_args.update(self.format_xml)
        url = 'objects/%s' % (pid, )
        r = self.get(url, params=http_args)
        return r.content, r.url

    def listDatastreams(self, pid):
        """
        Get a list of all datastreams for a specified object.

        Wrapper function for `Fedora REST API listDatastreams <http://fedora-commons.org/confluence/display/FCR30/REST+API#RESTAPI-listDatastreams>`_

        :param pid: string object pid
        :rtype: string xml data
        """
        # /objects/{pid}/datastreams ? [format, datetime]
        url = 'objects/%s/datastreams' % (pid, )
        r = self.get(url, params=self.format_xml)
        return r.content, r.url

    def listMethods(self, pid, sdefpid=None):
        # /objects/{pid}/methods ? [format, datetime]
        # /objects/{pid}/methods/{sdefpid} ? [format, datetime]
        
        ## NOTE: getting an error when sdefpid is specified; fedora issue?
        uri = 'objects/%s/methods' % pid
        if sdefpid:
            uri += '/' + sdefpid
    	r = self.get(uri, params=self.format_xml)
        return r.content, r.url

    ### API-M methods (management) ####

    def addDatastream(self, pid, dsID, dsLabel=None,  mimeType=None, logMessage=None,
        controlGroup=None, dsLocation=None, altIDs=None, versionable=None,
        dsState=None, formatURI=None, checksumType=None, checksum=None, content=None):
        # objects/{pid}/datastreams/NEWDS? [opts]
        # content via multipart file in request content, or dsLocation=URI
        # one of dsLocation or content must be specified

        # if checksum is sent without checksum type, Fedora seems to
        # ignore it (does not error on invalid checksum with no checksum type)
        if checksum is not None and checksumType is None:
            warnings.warn('Fedora will ignore the checksum (%s) because no checksum type is specified' \
                          % checksum)
            
        http_args = {'dsLabel': dsLabel, 'mimeType': mimeType}
        if logMessage:
            http_args['logMessage'] = logMessage
        if controlGroup:
            http_args['controlGroup'] = controlGroup
        if dsLocation:
            http_args['dsLocation'] = dsLocation
        if altIDs:
            http_args['altIDs'] = altIDs
        if versionable is not None:
            http_args['versionable'] = versionable
        if dsState:
            http_args['dsState'] = dsState
        if formatURI:
            http_args['formatURI'] = formatURI
        if checksumType:
            http_args['checksumType'] = checksumType
        if checksum:
            http_args['checksum'] = checksum

        # Added code to match how content is now handled, see modifyDatastream.
        content_args = {}
         # could be a string or a file-like object
        if content:
            if hasattr(content, 'read'):    # if content is a file-like object, warn if no checksum
                if not checksum:
                    logging.warning("File was ingested into fedora without a passed checksum for validation, pid was: %s and dsID was: %s." % (pid, dsID))

                content_args['files'] = {'file': content}
            else:
                content_args['data'] = content

            # set content-type header ? 
            
        url = 'objects/%s/datastreams/%s' % (pid, dsID)
        r = self.post(url, params=http_args, **content_args)
        # expected response: 201 Created (on success)
        # when pid is invalid, response body contains error message
        #  e.g., no path in db registry for [bogus:pid]
        # return success/failure and any additional information
        return (r.status_code == requests.codes.created, r.content)

    # addRelationship not implemented in REST API

    def compareDatastreamChecksum(self, pid, dsID, asOfDateTime=None): # date time
        # special case of getDatastream, with validateChecksum = true
        # currently returns datastream info returned by getDatastream...  what should it return?
        return self.getDatastream(pid, dsID, validateChecksum=True, asOfDateTime=asOfDateTime)

    def export(self, pid, context=None, format=None, encoding=None):
        # /objects/{pid}/export ? [format] [context] [encoding]
        # - if format is not specified, use fedora default (FOXML 1.1)
        # - if encoding is not specified, use fedora default (UTF-8)
        # - context should be one of: public, migrate, archive (default is public)
        http_args = {}
        if context:
            http_args['context'] = context
        if format:
            http_args['format'] = format
        if encoding:
            http_args['encoding'] = encoding
        uri = 'objects/%s/export' % pid

        r = self.get(uri, params=http_args)
        return r.content, r.url

    def getDatastream(self, pid, dsID, asOfDateTime=None, validateChecksum=False):
        """Get information about a single datastream on a Fedora object; optionally,
        get information for the version of the datastream as of a particular date time.

        :param pid: object pid
        :param dsID: datastream id
        :param asOfDateTime: optional datetime; ``must`` be a non-naive datetime
        so it can be converted to a date-time format Fedora can understand
        """
        # /objects/{pid}/datastreams/{dsID} ? [asOfDateTime] [format] [validateChecksum]
        http_args = {}
        if validateChecksum:
            # fedora only responds to lower-case validateChecksum option
            http_args['validateChecksum'] = str(validateChecksum).lower()
        if asOfDateTime:
            http_args['asOfDateTime'] = datetime_to_fedoratime(asOfDateTime)
        http_args.update(self.format_xml)
        uri = 'objects/%s/datastreams/%s' % (pid, dsID)
        r = self.get(uri, params=http_args)
        return r.content, r.url

    # getDatastreamHistory not implemented in REST API

    # getDatastreams not implemented in REST API

    def getNextPID(self, numPIDs=None, namespace=None):
        """
        Wrapper function for `Fedora REST API getNextPid <http://fedora-commons.org/confluence/display/FCR30/REST+API#RESTAPI-getNextPID>`_

        :param numPIDs: (optional) get the specified number of pids; by default, returns 1
        :param namespace: (optional) get the next pid in the specified pid namespace;
            otherwise, Fedora will return the next pid in the configured default namespace.
        :rtype: string (if only 1 pid requested) or list of strings (multiple pids)
        """
        http_args = { 'format': 'xml' }
        if numPIDs:
            http_args['numPIDs'] = numPIDs
        if namespace:
            http_args['namespace'] = namespace

        url = 'objects/nextPID'
        r = self.post(url, params=http_args)
        return r.content, r.url

    def getObjectXML(self, pid):
        """
           Return the entire xml for the specified object.

           :param pid: pid of the object to retrieve
           :param parse: optional data parser function; defaults to returning
                         raw string data
           :rtype: string xml content of entire object
        """
        # /objects/{pid}/objectXML
        url = 'objects/%s/objectXML' % (pid,)
        r = self.get(url)
        return r.content, r.url

    # getRelationships not implemented in REST API

    def ingest(self, text, logMessage=None):
        """
        Ingest a new object into Fedora. Returns the pid of the new object on success.

        Wrapper function for `Fedora REST API ingest <http://fedora-commons.org/confluence/display/FCR30/REST+API#RESTAPI-ingest>`_

        :param text: full text content of the object to be ingested
        :param logMessage: optional log message
        :rtype: string
        """

        # FIXME/TODO: add options for ingest with pid, values for label/format/namespace/ownerId, etc?
        http_args = {}
        if logMessage:
            http_args['logMessage'] = logMessage

        headers = { 'Content-Type': 'text/xml' }

        url = 'objects/new'
        r = self.post(url, text, params=http_args, headers=headers)
        return r.content  # content is new pid

    def modifyDatastream(self, pid, dsID, dsLabel=None, mimeType=None, logMessage=None, dsLocation=None,
        altIDs=None, versionable=None, dsState=None, formatURI=None, checksumType=None,
        checksum=None, content=None, force=False):   
        # /objects/{pid}/datastreams/{dsID} ? [dsLocation] [altIDs] [dsLabel] [versionable] [dsState] [formatURI] [checksumType] [checksum] [mimeType] [logMessage] [force] [ignoreContent]
        # NOTE: not implementing ignoreContent (unneeded)
        
        # content via multipart file in request content, or dsLocation=URI
        # if dsLocation or content is not specified, datastream content will not be updated
        # content can be string or a file-like object

        # Unlike addDatastream, if checksum is sent without checksum
        # type, Fedora honors it (*does* error on invalid checksum
        # with no checksum type) - it seems to use the existing
        # checksum type if a new type is not specified.


        http_args = {}
        if dsLabel:
            http_args['dsLabel'] = dsLabel
        if mimeType:
            http_args['mimeType'] = mimeType
        if logMessage:
            http_args['logMessage'] = logMessage
        if dsLocation:
            http_args['dsLocation'] = dsLocation
        if altIDs:
            http_args['altIDs'] = altIDs
        if versionable is not None:
            http_args['versionable'] = versionable
        if dsState:
            http_args['dsState'] = dsState
        if formatURI:
            http_args['formatURI'] = formatURI
        if checksumType:
            http_args['checksumType'] = checksumType
        if checksum:
            http_args['checksum'] = checksum
        if force:
            http_args['force'] = force

        content_args = {}
        if content:
            # content can be either a string or a file-like object
            if hasattr(content, 'read'):    # allow content to be a file
                # warn about missing checksums for files
                if not checksum:
                    logging.warning("Updating datastream %s/%s with a file, but no checksum passed" \
                                    % (pid, dsID))

                # FIXME: Fedora does not seem to accept multipart file content from PUT
                # the way requests wants to send it...
                # This will cause problems for large datastreams...
                content_args['data'] = content.read()
                #content_args['files'] = {'file': content}
            else:
                content_args['data'] = content

        url = 'objects/%s/datastreams/%s' % (pid, dsID)
        r = self.put(url, params=http_args, **content_args)

        # expected response: 200 (success)
        # response body contains error message, if any
        # return success/failure and any additional information
        return (r.status_code == requests.codes.ok, r.content)

    def modifyObject(self, pid, label, ownerId, state, logMessage=None):
        # /objects/{pid} ? [label] [ownerId] [state] [logMessage]
        http_args = {'label' : label,
                    'ownerId' : ownerId,
                    'state' : state}
        if logMessage is not None:
            http_args['logMessage'] = logMessage
            
        url = 'objects/%s' % (pid,)
        r = self.put(url, params=http_args, prefetch=True)
        # prefetch to immediately release the connection, since we
        # won't actually read the response content
        return r.status_code == requests.codes.ok

    def purgeDatastream(self, pid, dsID, startDT=None, endDT=None, logMessage=None,
            force=False):
        """
        Purge a datastream, or versions of a dastream, from a Fedora object.

        :param pid: object pid
        :param dsID: datastream ID
        :param startDT: optional start datetime (when purging certain versions)
        :param endDT: optional end datetime (when purging certain versions)
        :param logMessage: optional log message
        :returns: tuple of success/failure and response content; on success,
            response content is a list of timestamps for the datastream purged;
            on failure, response content may contain an error message
        """
        # /objects/{pid}/datastreams/{dsID} ? [startDT] [endDT] [logMessage] [force]
        http_args = {}
        if logMessage:
            http_args['logMessage'] = logMessage
        if startDT:
            http_args['startDT'] = startDT
        if endDT:
            http_args['endDT'] = endDT
        if force:
            http_args['force'] = force

        url = 'objects/%s/datastreams/%s' % (pid, dsID)
        r = self.delete(url, params=http_args)
        # as of Fedora 3.4, returns 200 on success with a list of the
        # timestamps for the versions deleted as response content
        # NOTE: response content may be useful on error, e.g.
        #       no path in db registry for [bogus:pid]
        # is there any useful way to pass this info back?
        # *NOTE*: bug when purging non-existent datastream on a valid pid
        # - reported here: http://www.fedora-commons.org/jira/browse/FCREPO-690
        # - as a possible work-around, could return false when status = 200
        #   but response body is an empty list (i.e., no datastreams/versions purged)
        return r.status_code == requests.codes.ok, r.content

    def purgeObject(self, pid, logMessage=None):
        """
        Purge an object from Fedora.

        Wrapper function for `REST API purgeObject <http://fedora-commons.org/confluence/display/FCR30/REST+API#RESTAPI-purgeObject>`_

        :param pid: pid of the object to be purged
        :param logMessage: optional log message
        """
        # FIXME: return success/failure?
        http_args = {}
        if logMessage:
            http_args['logMessage'] = logMessage

        url = 'objects/%s' % (pid, )
        r = self.delete(url, params=http_args)
        # as of Fedora 3.4, returns 200 on success; response content is timestamp
        return r.status_code == requests.codes.ok, r.content

    # purgeRelationship not implemented in REST API

    def setDatastreamState(self, pid, dsID, dsState):
        # /objects/{pid}/datastreams/{dsID} ? [dsState]
        http_args = { 'dsState' : dsState }

        url = 'objects/%s/datastreams/%s' % (pid, dsID)
        r = self.put(url, params=http_args)  # prefetch ?
        # returns response code 200 on success
        return r.status_code == requests.codes.ok

    def setDatastreamVersionable(self, pid, dsID, versionable):
        # /objects/{pid}/datastreams/{dsID} ? [versionable]
        http_args = { 'versionable' : versionable }
        url = 'objects/%s/datastreams/%s' % (pid, dsID)
        r = self.put(url, params=http_args)
        # returns response code 200 on success
        return r.status_code == requests.codes.ok


# NOTE: the "LITE" APIs are planned to be phased out; when that happens, these functions
# (or their equivalents) should be available in the REST API

class API_A_LITE(HTTP_API_Base):
    """
       Python object for accessing `Fedora's API-A-LITE <http://fedora-commons.org/confluence/display/FCR30/API-A-LITE>`_.
    """
    def describeRepository(self):
        """
        Get information about a Fedora repository.

        :rtype: string
        """
        http_args = { 'xml': 'true' }
        r = self.get('describe', params=http_args)
        return r.content, r.url

class API_M_LITE(HTTP_API_Base):
    def upload(self, data):
        url = 'management/upload'

        # fedora only expects content uploaded as multipart file
        # - make string content into a file-like object so requests.post
        # sends it the way Fedora expects.
        if not hasattr(data, 'read'):
            data = StringIO(data)
        r = self.post(url, files={'file': data})
        # returns 201 Created on success
        # content of response should be upload id, if successful
        return r.content.strip()


# return object for getRelationships soap call
class GetRelationshipResponse:
    def __init__(self, relationships):
        self.relationships = relationships

    @staticmethod
    def from_xml(*elements):
        return GetRelationshipResponse([RelationshipTuple.from_xml(el)
                                        for el in elements])

    
class RelationshipTuple(ClassSerializer):
    class types:
        subject = soap_types.String
        predicate = soap_types.String
        object = soap_types.String
        isLiteral = soap_types.Boolean
        datatype = soap_types.String

class GetDatastreamHistoryResponse:
    def __init__(self, datastreams):
        self.datastreams = datastreams

    @staticmethod
    def from_xml(*elements):
        return GetDatastreamHistoryResponse([Datastream.from_xml(el)
                                             for el in elements])

class Datastream(ClassSerializer):
    # soap datastream response used by getDatastreamHistory and getDatastream
    class types:
        controlGroup = soap_types.String
        ID = soap_types.String
        versionID = soap_types.String
        altIDs = soap_types.String   # according to Fedora docs this should be array, but that doesn't work
        label = soap_types.String
        versionable = soap_types.Boolean
        MIMEType = soap_types.String
        formatURI = soap_types.String
        createDate = soap_types.DateTime
        size = soap_types.Integer   # Long ?
        state = soap_types.String
        location = soap_types.String
        checksumType = soap_types.String
        checksum = soap_types.String
    
# service class stub for soap method definitions
class API_M_Service(SimpleWSGISoapApp):
    """
       Python object for accessing `Fedora's SOAP API-M <http://fedora-commons.org/confluence/display/FCR30/API-M>`_.
    """
    # FIXME: also accepts an optional String datatype
    @soapmethod(
            soap_types.String,  # pid       NOTE: fedora docs say URI, but at least in 3.2 it's really pid
            soap_types.String,  # relationship
            soap_types.String,  # object
            soap_types.Boolean, # isLiteral
            _outVariableName='added',
            _returns = soap_types.Boolean)
    def addRelationship(self, pid, relationship, object, isLiteral):
        """
        Add a new relationship to an object's RELS-EXT datastream.

        Wrapper function for `API-M addRelationship <http://fedora-commons.org/confluence/display/FCR30/API-M#API-M-addRelationship>`_

        :param pid: object pid
        :param relationship: relationship to be added
        :param object: URI or string for related object
        :param isLiteral: boolean, is the related object a literal or an rdf resource
        """
        pass

    @soapmethod(
            soap_types.String,  # subject (fedora object or datastream URI) 
            soap_types.String,  # relationship
            _outVariableName='relationships',
            _returns = GetRelationshipResponse)   # custom class for complex soap type
    def getRelationships(self, subject=None, relationship=None):
        pass

    @soapmethod(
            soap_types.String,  # pid
            soap_types.String,  # relationship; null matches all
            soap_types.String,  # object; null matches all
            soap_types.Boolean, # isLiteral     # optional literal datatype ?
            _returns = soap_types.Boolean,
            _outVariableName='purged',)
    def purgeRelationship(self, pid, relationship=None, object=None, isLiteral=False):
        pass

    @soapmethod(
            soap_types.String,  #pid
            soap_types.String,  #dsID
            _returns = GetDatastreamHistoryResponse,
            _outVariableName="datastream")
    def getDatastreamHistory(self, pid, dsID):
        pass


# extend SimpleSoapClient to accept auth headers and pass them to any soap call that is made
class AuthSoapClient(SimpleSoapClient):
    def __init__(self, host, path, descriptor, scheme="http", auth_headers={}):
        self.auth_headers = auth_headers
        return super(AuthSoapClient, self).__init__(host, path, descriptor, scheme)

    def __call__(self, *args, **kwargs):
        kwargs.update(self.auth_headers)
        return super(AuthSoapClient, self).__call__(*args, **kwargs)


class API_M(ServiceClient):
    def __init__(self, base_url, username=None, password=None):
        self.auth_headers = auth_headers(username, password)
        urlparts = urlsplit(base_url)
        hostname = urlparts.hostname
        api_path = urlparts.path + 'services/management'
        if urlparts.port:
            hostname += ':%s' % urlparts.port

        # this is basically equivalent to calling make_service_client or ServiceClient init
        # - using custom AuthSoapClient and passing auth headers
        self.server = API_M_Service()
        for method in self.server.methods():
            setattr(self, method.name, AuthSoapClient(hostname, api_path, method,
                urlparts.scheme, self.auth_headers))


class ApiFacade(REST_API, API_A_LITE, API_M_LITE, API_M): # there is no API_A today
    """Pull together all Fedora APIs into one place."""
    def __init__(self, base_url, username=None, password=None):
        HTTP_API_Base.__init__(self, base_url, username, password)
        API_M.__init__(self, base_url, username, password)



class UnrecognizedQueryLanguage(EnvironmentError):
    pass

class ResourceIndex(HTTP_API_Base):
    "Python object for accessing Fedora's Resource Index."

    RISEARCH_FLUSH_ON_QUERY = False
    """Specify whether or not RI search queries should specify flush=true to obtain
    the most recent results.  If flush is specified to the query method, that
    takes precedence.

    Irrelevant if Fedora RIsearch is configured with syncUpdates = True.
    """

    def find_statements(self, query, language='spo', type='triples', flush=None):
        """
        Run a query in a format supported by the Fedora Resource Index (e.g., SPO
        or Sparql) and return the results.

        :param query: query as a string
        :param language: query language to use; defaults to 'spo'
        :param type: type of query - tuples or triples; defaults to 'triples'
        :param flush: flush results to get recent changes; defaults to False
        :rtype: :class:`rdflib.ConjunctiveGraph` when type is ``triples``; list
            of dictionaries (keys based on return fields) when type is ``tuples``
        """
        http_args = {
            'type': type,
            'lang': language,
            'query': query,
        }
        if type == 'triples':
            format = 'N-Triples'
        elif type == 'tuples':
            format = 'CSV'
        # else - error/exception ?
        http_args['format'] = format

        return self._query(format, http_args, flush)

    def count_statements(self, query, language='spo', type='triples',
                         flush=None):
        """
        Run a query in a format supported by the Fedora Resource Index
        (e.g., SPO or Sparql) and return the count of the results.

        :param query: query as a string
        :param language: query language to use; defaults to 'spo'
        :param flush: flush results to get recent changes; defaults to False
        :rtype: integer
        """
        format = 'count'
        http_args = {
            'type': type,
            'lang': language,
            'query': query,
            'format': format
        }
        return self._query(format, http_args, flush)


    def _query(self, format, http_args, flush=None):
        # if flush parameter was not specified, use class setting
        if flush is None:
            flush = self.RISEARCH_FLUSH_ON_QUERY
        http_args['flush'] = 'true' if flush else 'false'
        
        risearch_url = 'risearch?'
        try:
            r = self.get(risearch_url, params=http_args)
            # parse the result according to requested format
            if format == 'N-Triples':
                return parse_rdf(r.content, r.url, format='n3')
            elif format == 'CSV':
                # reader expects a file or a list; for now, just split the string
                # TODO: when we can return url contents as file-like objects, use that
                return csv.DictReader(r.iter_lines())
            elif format == 'count':
                return int(r.content)
            
            # should we return the response as fallback? 
        except RequestFailed, f:
            if 'Unrecognized query language' in f.detail:
                raise UnrecognizedQueryLanguage(f.detail)
            # could also see 'Unsupported output format' 
            else:
                raise f
        

    def spo_search(self, subject=None, predicate=None, object=None):
        """
        Create and run a subject-predicate-object (SPO) search.  Any search terms
        that are not specified will be replaced as a wildcard in the query.

        :param subject: optional subject to search
        :param predicate: optional predicate to search
        :param object: optional object to search
        :rtype: :class:`rdflib.ConjunctiveGraph`
        """
        spo_query = '%s %s %s' % \
                (self.spoencode(subject), self.spoencode(predicate), self.spoencode(object))
        return self.find_statements(spo_query)

    def spoencode(self, val):
        """
        Encode search terms for an SPO query.

        :param val: string to be encoded
        :rtype: string
        """
        if val is None:
            return '*'
        elif "'" in val:    # FIXME: need better handling for literal strings
            return val
        else:
            return '<%s>' % (val,)

    def get_subjects(self, predicate, object):
        """
        Search for all subjects related to the specified predicate and object.

        :param predicate:
        :param object:
        :rtype: generator of RDF statements
        """
        for statement in self.spo_search(predicate=predicate, object=object):
            yield str(statement[0])

    def get_predicates(self, subject, object):
        """
        Search for all subjects related to the specified subject and object.

        :param subject:
        :param object:
        :rtype: generator of RDF statements
        """
        for statement in self.spo_search(subject=subject, object=object):
            yield str(statement[1])

    def get_objects(self, subject, predicate):
        """
        Search for all subjects related to the specified subject and predicate.

        :param subject:
        :param object:
        :rtype: generator of RDF statements
        """
        for statement in self.spo_search(subject=subject, predicate=predicate):
            yield str(statement[2])

    def sparql_query(self, query, flush=None):
        """
        Run a Sparql query.

        :param query: sparql query string
        :rtype: list of dictionary
        """
        return self.find_statements(query, language='sparql', type='tuples', flush=flush)


