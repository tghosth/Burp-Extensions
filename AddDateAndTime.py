from burp import IBurpExtender
from burp import ISessionHandlingAction
import time
import traceback

'''
Name:           Add Date and Time
Version:        1.0
Date:           22-Feb-18
Author:         Josh Grossman
Github:         https://github.com/tghosth/Burp-Extensions

This extension is designed to provide a session handling rule which just adds the current date and time to a request.

I originally wanted this so I could show a chronological sequence of requests in repeater. I have not tested it in other
tools within Burp.

I based the code on this: https://support.portswigger.net/customer/portal/questions/12695799-adding-a-header-with-isessionhandlingaction
I did have to add the getActionName function and I don't know whether that is because the API was different in 2015
or what
'''

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    name = "Add Date and Time"

    def registerExtenderCallbacks(self, callbacks):
        try:
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()
            callbacks.setExtensionName(self.name)
            callbacks.registerSessionHandlingAction(self)
        except:
            tb = traceback.format_exc()
            print tb

    #                       IHttpRequestResponse   IHttpRequestResponse[]
    def performAction(self, currentRequest,        macroItems):

        # IRequestInfo
        requestInfo = self._helpers.analyzeRequest(currentRequest)

        headers = requestInfo.getHeaders()

        # Define a new headers object to rebuild the request with
        headersNew = []

        # Get the body as this will be needed to rebuild the request afterwards
        reqBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]

        # Copy all headers into the new header object except if there was a previous date time header in there
        for header in headers:
            if 'X-Date-Time' not in header:
                headersNew.append(header)

        # Add a date time header to the new headers object formated like this: Thu Feb 22 09:55:23 2018
        headersNew.append('X-Date-Time: {0}'.format(time.strftime("%c")))

        # rebuild the request object and update the originally passed in IHttpRequestResponse object
        message = self._helpers.buildHttpMessage(headersNew, reqBody)
        currentRequest.setRequest(message)


    def getActionName(self):
        return self.name


