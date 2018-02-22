from burp import IBurpExtender
from burp import IProxyListener
import json as json
import traceback

'''
Name:           Proxy Listener Status Header
Version:        1.0
Date:           13-Feb-18
Author:         Josh Grossman
Github:         https://github.com/tghosth/Burp-Extensions

This extension is designed to print the current proxy state as a header in requests. The rationale is that sometimes
I want to test whether a client-side/mobile application is verifying the server side TLS certificate or not and I do
this by trying to run the application using a self-signed certificate.

This extension makes it easy afterwards to see which requests were sent using a self signed certificate and which proxy 
listener was used.

Note that by default the local proxy listener IP and port is disclosed in the header. This can be suppressed using the 
disclose_ip and disclose_port flags below. You can also add friendly text for the header to replace the Burp config text
using the friendly_descriptions dictionary, change the name of the extension as it appears in Burp Suite using the 
name variable and change the name of the header which is inserted into the request using the proxy_header_name variable.

Note that this extension obviously requires that Jython is available to Burp
'''

class BurpExtender(IBurpExtender, IProxyListener):
    # The name that the extension will be shown with in Burp Suite
    name = 'Proxy Listener Status Header'

    # I have added some transforms here to change the default Burp TLS mode description to something more friendly
    # You could add others if you wanted to.
    friendly_descriptions = {'per_host': 'Valid, Proxy Certificate',
                             'self_signed': 'Invalid Self-Signed Certificate'}

    # Set the name that will be given to the header
    proxy_header_name = 'X-Burp-Mode'

    # Should the added header disclose the local proxy IP
    disclose_ip = True

    # Should the added header disclose the local proxy disclose the local port
    disclose_port = True

    def registerExtenderCallbacks(self, callbacks):
        try:
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()
            callbacks.setExtensionName(self.name)
            callbacks.registerProxyListener(self)
        except:
            tb = traceback.format_exc()
            print tb
        return

    # , boolean , IInterceptedProxyMessage
    def processProxyMessage(self, messageIsRequest, proxyMessage):

        # proxyMessage can be either a request or a response and we only want to modify if it is a request
        if messageIsRequest:

            # IHttpRequestResponse
            message_info = proxyMessage.getMessageInfo()

            # getListenerInterface tells us which proxy listener the request is from in one of the forms below:
            # Localhost only - 127.0.0.1:8080 (where 8080 is the port number)
            # Specific interface only - 192.168.11.1:8080 (where 192.168.11.1 is the IP of the relevant interface and
            #                                               8080 is the port number)
            # ALl interfaces - *:8080 (where 8080 is the port number)

            # Get the IP from getListenerInterface
            current_listener_ip = proxyMessage.getListenerInterface().split(':')[0]

            # I prefer 0.0.0.0 notation to * hence the change here
            if current_listener_ip == '*':
                current_listener_ip = '0.0.0.0'

            # Get the port from getListenerInterface
            current_listener_port = int(proxyMessage.getListenerInterface().split(':')[1])

            # IRequestInfo
            request_info = self._helpers.analyzeRequest(message_info)

            # pull out the collection of headers in the request
            headers = request_info.getHeaders()

            # pull out the body from the request so that we can reassemble the request later
            req_body = message_info.getRequest()[request_info.getBodyOffset():]

            # Get the list of currently configured proxy listeners and parse the JSON
            proxy_list = json.loads(self._callbacks.saveConfigAsJson('proxy.request_listeners'))

            # iterate through the listeners so that we can find the one that caught this request and get the TLS status
            for proxy_entry in proxy_list['proxy']['request_listeners']:

                # We only want to look at listeners which are currently activated
                if proxy_entry['running']:

                    # We can firstly check that the port matches the listener port from the request,
                    # otherwise, we are not interested.
                    if current_listener_port == proxy_entry['listener_port']:

                        # The slightly painful logic required to check that the listener IP/mode matches.
                        if (
                                (current_listener_ip == '0.0.0.0' and (proxy_entry['listen_mode'] == 'all_interfaces'))
                                or
                                (current_listener_ip == '127.0.0.1' and (proxy_entry['listen_mode'] == 'loopback_only'))
                                or
                                (current_listener_ip == proxy_entry['listen_specific_address'])
                        ):

                            # We should now be in the correct listener
                            # We can now pull out the TLS mode
                            proxy_tls_mode = proxy_entry['certificate_mode']

                            # Transform to friendly descriptions if an alternative exists
                            if proxy_tls_mode in self.friendly_descriptions:
                                proxy_tls_mode = self.friendly_descriptions[proxy_tls_mode]

                            # Form up the header content based on the data we have gathered and the disclosure settings
                            proxy_setting = ''
                            if self.disclose_ip and self.disclose_port:
                                proxy_setting = '{0}:{1} - '.format(current_listener_ip, current_listener_port)
                            else:
                                if self.disclose_port:
                                    proxy_setting = 'Proxy Port: {0} - '.format(current_listener_port)
                                elif self.disclose_ip:
                                    proxy_setting = 'Proxy IP: {0} - '.format(current_listener_ip)

                            proxy_setting = '{0}TLS Mode: {1}'.format(proxy_setting, proxy_tls_mode)

                            # The header shouldn't already exist but we want to check if it does.
                            header_exists = False
                            for header in headers:
                                if self.proxy_header_name in header:
                                    header_exists = True
                                    break

                            # If the header doesn't already exist then we add it
                            if not header_exists:
                                headers.add('{0}: {1}'.format(self.proxy_header_name, proxy_setting))

                            # We can now break out of the listener iterator, we are at the correct place
                            break

            # Build the request again (with the updated header object)
            message = self._helpers.buildHttpMessage(headers, req_body)

            # Update the request content
            message_info.setRequest(message)
