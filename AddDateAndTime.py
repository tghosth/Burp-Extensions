from burp import IBurpExtender
from burp import ISessionHandlingAction
import time
import traceback

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

    def performAction(self, currentRequest, macroItems):

        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = requestInfo.getHeaders()
        reqBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        headers.add('X-Date-Time: {0}'.format(time.strftime("%c")))
        message = self._helpers.buildHttpMessage(headers, reqBody)
        currentRequest.setRequest(message)


    def getActionName(self):
        return self.name


