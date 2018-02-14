from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
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
        callbacks.setExtensionName("Custom scanner checks")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
            return None




    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # make a request containing our injection test in the insertion point

        if not insertionPoint.getInsertionPointType == insertionPoint.INS_URL_PATH_FILENAME:
            return None

        funcName = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))

        checkRequest = insertionPoint.buildRequest(INJ_TEST)
        checkRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest)

        # look for matches of our active check grep string
        matches = self._get_matches(checkRequestResponse.getResponse(), INJ_ERROR_BYTES)
        if len(matches) == 0:
            return None

        # get the offsets of the payload within the request, for in-UI highlighting
        requestHighlights = [insertionPoint.getPayloadOffsets(INJ_TEST)]

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)],
            "Pipe injection",
            "Submitting a pipe character returned the string: " + INJ_ERROR,
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