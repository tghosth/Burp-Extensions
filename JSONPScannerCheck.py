from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IParameter

import random
import string
from array import array



class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("JSONP Scanner Check")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        pass

    # Parameter names from https://securitycafe.ro/2017/01/18/practical-jsonp-injection/ :)
    paramNames = {'callback', 'cb', 'jsonp', 'jsonpcallback', 'jcb', 'call'}

    def doActiveScan(self, baseRequestResponse, insertionPoint):

        # We only want to apply this check once per request, this insertion point seems to be the most sensible.
        if not insertionPoint.getInsertionPointType() == insertionPoint.INS_PARAM_NAME_URL:
            return None

        # Iterate through the list of potential JSONP parameter names
        for paramName in self.paramNames:

            # Get a random (non cryptographically secure) six letter string to assign the parameter value
            funcName = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))

            # Get the raw base request being scanned
            requestRaw = baseRequestResponse.getRequest()

            # build a JSONP parameter using the current parameter name and the random string generated
            newParameter = self._helpers.buildParameter(paramName, funcName, IParameter.PARAM_URL)

            # add the parameter to the base request
            checkRequest = self._helpers.addParameter(requestRaw, newParameter)

            # send the request with the added parameter
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest)

            # look for matches of our active check grep string
            matches = self._get_matches(checkRequestResponse.getResponse(), '{0}('.format(funcName))
            if not len(matches) == 0:
                # get the offsets of the payload within the request, for in-UI highlighting
                requestHighlights = [insertionPoint.getPayloadOffsets('{0}={1}'.format(paramName, funcName))]

                # report the issue
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)],
                    "JSONP detected",
                    "Adding a parameter with the name \"{0}\" resulted in a JSONP response".format(paramName),
                    "High")]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL
        # path by the same extension-provided check. The value we return from this
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches


    def getInsertionPointText(self, insertionPointIn):
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_ENTIRE_BODY: return "INS_ENTIRE_BODY"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_EXTENSION_PROVIDED: return "INS_EXTENSION_PROVIDED"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_HEADER: return "INS_HEADER"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_AMF: return "INS_PARAM_AMF"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_BODY: return "INS_PARAM_BODY"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_COOKIE: return "INS_PARAM_COOKIE"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_JSON: return "INS_PARAM_JSON"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_MULTIPART_ATTR: return "INS_PARAM_MULTIPART_ATTR"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_NAME_BODY: return "INS_PARAM_NAME_BODY"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_NAME_URL: return "INS_PARAM_NAME_URL"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_URL: return "INS_PARAM_URL"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_XML: return "INS_PARAM_XML"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_PARAM_XML_ATTR: return "INS_PARAM_XML_ATTR"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_UNKNOWN: return "INS_UNKNOWN"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_URL_PATH_FILENAME: return "INS_URL_PATH_FILENAME"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_URL_PATH_FOLDER: return "INS_URL_PATH_FOLDER"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_URL_PATH_REST: return "INS_URL_PATH_REST"
        if insertionPointIn.getInsertionPointType() == insertionPointIn.INS_USER_PROVIDED: return "INS_USER_PROVIDED"
#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

