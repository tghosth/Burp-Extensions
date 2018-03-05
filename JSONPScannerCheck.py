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

    #                      IHttpRequestResponse IScannerInsertionPoint
    def doActiveScan(self, baseRequestResponse, insertionPoint):

        # We only want to apply this check once per request, this insertion point seems to be the most sensible.
        if not insertionPoint.getInsertionPointType() == insertionPoint.INS_PARAM_NAME_URL:
            return None

        # Get the raw base request (byte[]) being scanned
        requestRaw = baseRequestResponse.getRequest()

        # Gets the http service to use to send the requests
        httpService = baseRequestResponse.getHttpService()

        # Gets the info object for this request/response pair
        requestInfo = self._helpers.analyzeRequest(baseRequestResponse)

        # Iterate through the list of potential JSONP parameter names
        for paramName in self.paramNames:

            # Testing to see if the original request provides a JSONP response for the current parameter.
            originalResponseWithMarkers = self._testForJSONP(httpService, requestRaw, paramName, insertionPoint)

            # If not then we will skip the rest of the code
            if len(originalResponseWithMarkers.getResponseMarkers()) != 0:

                '''
                We now know that the request returns a JSONP response but we now want to establish whether the endpoint
                we have discovered it on requires some form of authentication. 
                
                If so then this is a high risk issue as sensitive data is almost certainly being disclosed. 
                
                If not then this is a medium risk issue as it is possible that the data is not sensitive but it may
                still be intended to only be accessed from a particular IP or network so we still raise as an issue.
                '''

                # First we are going to remove any cookies from the request and see whether this resulted in any changes.
                reqWithChanges = self._removeAllCookies(requestRaw, requestInfo)
                reqCookieChanged = (len(reqWithChanges) != len(requestRaw))

                # Next we are going to remove any 'Authorization' header and see whether either of these actions
                # resulted in a change
                reqWithChanges2 = self._removeAuthHeader(reqWithChanges, requestInfo)
                reqChanged = reqCookieChanged | (len(reqWithChanges) != len(reqWithChanges2))

                # This will be the finding text if the request has not changed or if the same JSONP response is received
                # even after removing the cookies/Authorization header
                rating = "Medium"
                addText = "The JSONP response was returned even without cookies or an Authorization header " \
                          "indicating that the data returned may be less sensitive"

                reqList = [originalResponseWithMarkers]

                # If the request changed (i.e. cookies or Authorization header were removed.)
                if reqChanged:
                    # Send the request again to try and get a JSONP response without the cookies/Authorization header
                    nocookieResponseWithMarkers = self._testForJSONP(httpService, reqWithChanges2, paramName, insertionPoint)

                    # We want the changed request returned with the finding either way
                    reqList.append(nocookieResponseWithMarkers)

                    # If there are no response markers then this means that when sending with the cookies/Authorization
                    # header we received a JSONP response but without these we did not receive a JSONP response. This
                    # indicates that authentication is required for this API therefore raising the rating to High.
                    if len(nocookieResponseWithMarkers.getResponseMarkers()) == 0:
                        rating = "High"
                        addText = "The JSONP response was not returned when cookies or an Authorization header " \
                                  "was not sent indicating that the data is likely to be sensitive"

                # report the issue
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    reqList,
                    "Endpoint supporting JSONP detected",
                    "Adding a parameter with the name \"{0}\" resulted in a JSONP response. {1}".format(paramName, addText),
                    rating)]


    '''
    Sends a modified request based on the original request with the supplied JSONP parameter added at the insertion 
    point specified.
    '''
    def _testForJSONP(self, httpService, requestRaw, paramName, insertionPoint):
        # Get a random (non cryptographically secure) six letter string to assign the parameter value
        funcName = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))



        # build a JSONP parameter (IParameter) using the current parameter name and the random string generated
        newParameter = self._helpers.buildParameter(paramName, funcName, IParameter.PARAM_URL)

        # add the parameter to the base request (byte[])
        checkRequest = self._helpers.addParameter(requestRaw, newParameter)

        # send the request with the added parameter and receive back IHttpRequestResponse
        checkRequestResponse = self._callbacks.makeHttpRequest(httpService, checkRequest)

        print len(checkRequestResponse.getRequest())
        print 'Params:'
        for aa in self._helpers.analyzeRequest(checkRequestResponse.getRequest()).getParameters():
            print aa.getName()
            print aa.getValue()

        # look for matches of our active check grep string
        matches = self._get_matches(checkRequestResponse.getResponse(), '{0}('.format(funcName))
        print matches
        if not len(matches) == 0:
            # get the offsets of the payload within the request, for in-UI highlighting
            requestHighlights=  [insertionPoint.getPayloadOffsets('{0}={1}'.format(paramName, funcName))]
            return self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)

        return self._callbacks.applyMarkers(checkRequestResponse, None, None)


    '''
    This will remove all cookies from a request.
    '''
    def _removeAllCookies(self, requestRaw, requestInfo):
        reqWithChanges = requestRaw

        # Iterate through the parameters in the request
        for reqParam in requestInfo.getParameters():
            # we only want to remove parameters which are cookies.
            if reqParam.getType() == IParameter.PARAM_COOKIE:
                reqWithChanges = self._helpers.removeParameter(reqWithChanges, reqParam)

        return reqWithChanges

    '''
    This will remove all headers containing the word 'Authorization'.
    '''
    def _removeAuthHeader(self, requestRaw, requestInfo):
        reqWithChanges = requestRaw

        # Get the list of headers and create a new object to pass the headers into
        oldHeaders = requestInfo.getHeaders()
        newHeaders = []

        # Put all headers into the new object unless they contain the word 'Authorization'
        for reqHead in oldHeaders:
            if not 'Authorization' in reqHead:
                newHeaders.append(reqHead)

        # If a header has been removed, rebuild the request with the new header list
        if (len(oldHeaders) != len(newHeaders)):
            reqWithChanges = self._helpers.buildHttpMessage(newHeaders, requestRaw[requestInfo.getBodyOffset():])

        return reqWithChanges

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
    # From: https://github.com/PortSwigger/example-scanner-checks/blob/master/python/CustomScannerChecks.py
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

