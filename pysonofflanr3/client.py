import json
import logging
import time
from typing import Dict, Union, Callable, Awaitable
import asyncio
import traceback
import collections
import requests
from zeroconf import ServiceBrowser, Zeroconf
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pysonofflanr3 import sonoffcrypto
from pysonofflanr3 import utils
import socket


class SonoffLANModeClient:
    """
    Implementation of the Sonoff LAN Mode Protocol R3

    Uses protocol as was documented by Itead

    This document has since been unpublished
    """

    """
    Initialise class with connection parameters

    :param str host: host name (is ip address)
    :param device_id: the device name in the mDS servie name
    :return:
    """

    DEFAULT_TIMEOUT = 5
    DEFAULT_PING_INTERVAL = 5
    SERVICE_TYPE = "_ewelink._tcp.local."

    # only a single zeroconf instance for all instances of this class
    zeroconf = Zeroconf()

    def __init__(
        self,
        host: str,
        event_handler: Callable[[str], Awaitable[None]],
        ping_interval: int = DEFAULT_PING_INTERVAL,
        timeout: int = DEFAULT_TIMEOUT,
        logger: logging.Logger = None,
        loop=None,
        device_id: str = "",
        api_key: str = "",
        outlet: int = None,
    ):

        self.host = host
        self.device_id = device_id
        self.api_key = api_key
        self.outlet = outlet
        self.logger = logger
        self.event_handler = event_handler
        self.connected_event = asyncio.Event()
        self.disconnected_event = asyncio.Event()
        self.service_browser = None
        self.loop = loop
        self.http_session = None
        self.my_service_name = None
        self.last_request = None
        self.encrypted = False
        self.type = None
        self._info_cache = None
        self._last_params = {"switch": "off"}
        self._times_added = 0

    def listen(self):
        """
        Setup a mDNS listener
        """

        # listen for any added SOnOff
        self.service_browser = ServiceBrowser(
            SonoffLANModeClient.zeroconf,
            SonoffLANModeClient.SERVICE_TYPE,
            listener=self,
        )

    def close_connection(self):

        self.logger.debug("enter close_connection()")
        self.service_browser = None
        self.disconnected_event.set()
        self.my_service_name = None

    def remove_service(self, zeroconf, type, name):

        if self.my_service_name == name:
            self._info_cache = None
            self.logger.debug("Service %s flagged for removal" % name)
            self.loop.run_in_executor(None, self.retry_connection)

    def add_service(self, zeroconf, type, name):

        if self.my_service_name is not None:

            if self.my_service_name == name:
                self._times_added += 1
                self.logger.info(
                    "Service %s added again (%s times)"
                    % (name, self._times_added)
                )
                self.my_service_name = None
                asyncio.run_coroutine_threadsafe(
                    self.event_handler({}), self.loop
                )

        if self.my_service_name is None:

            info = zeroconf.get_service_info(type, name)
            found_ip = utils.parseAddress(info.addresses[0])

            if self.device_id is not None:

                if (
                    name
                    == "eWeLink_"
                    + self.device_id
                    + "."
                    + SonoffLANModeClient.SERVICE_TYPE
                ):
                    self.my_service_name = name

            elif self.host is not None:

                try:

                    if socket.gethostbyname(self.host) == found_ip:
                        self.my_service_name = name

                except TypeError:

                    if self.host == found_ip:
                        self.my_service_name = name

            if self.my_service_name is not None:

                self.logger.info(
                    "Service type %s of name %s added", type, name
                )

                self.create_http_session()
                self.set_retries(0)

                # process the initial message
                self.update_service(zeroconf, type, name)

    def update_service(self, zeroconf, type, name):

        data = None

        # This is needed for zeroconf 0.24.1
        # onwards as updates come to the parent node
        if self.my_service_name != name:
            return

        info = zeroconf.get_service_info(type, name)
        found_ip = utils.parseAddress(info.addresses[0])
        self.set_url(found_ip, str(info.port))

        # Useful optimsation for 0.24.1 onwards (fixed in 0.24.5 though)
        # as multiple updates that are the same are received
        if info.properties == self._info_cache:
            self.logger.info("same update received for device: %s", name)
            return
        else:
            self._info_cache = info.properties

        try:

            self.logger.debug("properties: %s", info.properties)

            self.type = info.properties.get(b"type")
            self.logger.debug("type: %s", self.type)

            data1 = info.properties.get(b"data1")
            data2 = info.properties.get(b"data2")

            if data2 is not None:
                data1 += data2
                data3 = info.properties.get(b"data3")

                if data3 is not None:
                    data1 += data3
                    data4 = info.properties.get(b"data4")

                    if data4 is not None:
                        data1 += data4

            if info.properties.get(b"encrypt"):

                if self.api_key == "" or self.api_key is None:
                    self.logger.error(
                        "Missing api_key for encrypted device: %s", name
                    )
                    data = None

                else:
                    self.encrypted = True
                    # decrypt the message
                    iv = info.properties.get(b"iv")
                    data = sonoffcrypto.decrypt(data1, iv, self.api_key)
                    self.logger.debug("decrypted data: %s", data)

            else:
                self.encrypted = False
                data = data1

            self.properties = info.properties

        except ValueError as ex:
            self.logger.error(
                "Error updating service for device %s: %s"
                " Probably wrong API key.",
                self.device_id,
                format(ex),
            )

        except Exception as ex:  # pragma: no cover
            self.logger.error(
                "Error updating service for device %s: %s, %s",
                self.device_id,
                format(ex),
                traceback.format_exc(),
            )

        finally:
            # process the events on an event loop
            # this method is on a background thread called from zeroconf
            asyncio.run_coroutine_threadsafe(
                self.event_handler(data), self.loop
            )

    def retry_connection(self):

        while True:
            try:
                self.logger.debug(
                    "Sending retry message for %s" % self.device_id
                )

                # in retry connection, we automatically retry 3 times
                self.set_retries(3)
                self.send_signal_strength()
                self.logger.info(
                    "Service %s flagged for removal, but is still active!"
                    % self.device_id
                )
                break

            except OSError as ex:
                self.logger.debug(
                    "Connection issue for device %s: %s",
                    self.device_id,
                    format(ex),
                )
                self.logger.info("Service %s removed" % self.device_id)
                self.close_connection()
                break

            except Exception as ex:  # pragma: no cover
                self.logger.error(
                    "Retry_connection() Unexpected error for device %s: %s %s",
                    self.device_id,
                    format(ex),
                    traceback.format_exc(),
                )
                break

            finally:
                # set retires back to 0
                self.set_retries(0)

    def send_switch(self, request: Union[str, Dict]):

        if self.type == b"strip":
            response = self.send(request, self.url + "/zeroconf/switches")
        else:
            response = self.send(request, self.url + "/zeroconf/switch")

        try:
            response_json = json.loads(response.content.decode("utf-8"))

            error = response_json["error"]

            if error != 0:
                self.logger.warning(
                    "error received: %s, %s", self.device_id, response.content
                )
                # no need to process error, retry will resend message

            else:
                self.logger.debug("message sent to switch successfully")
                # nothing to do, update is processed via the mDNS update

            return response

        except Exception as ex:  # pragma: no cover
            self.logger.error(
                "error %s processing response: %s, %s",
                format(ex),
                response,
                response.content,
            )

    def send_signal_strength(self):

        response = self.send(
            self.get_update_payload(self.device_id, {}),
            self.url + "/zeroconf/signal_strength",
        )

        if response.status_code == 500:
            self.logger.error("500 received")
            raise OSError

        else:
            return response

    def send(self, request: Union[str, Dict], url):
        """
        Send message to an already-connected Sonoff LAN Mode Device
        and return the response.
        :param request: command to send to the device (can be dict or json)
        :return:
        """

        data = json.dumps(request, separators=(",", ":"))
        self.logger.debug("Sending http message to %s: %s", url, data)
        response = self.http_session.post(url, data=data)
        self.logger.debug(
            "response received: %s %s", response, response.content
        )

        return response

    def get_update_payload(self, device_id: str, params: dict) -> Dict:

        self._last_params = params

        if self.type == b"strip" and params != {} and params is not None:

            if self.outlet is None:
                self.outlet = 0

            switches = {"switches": [{"switch": "off", "outlet": 0}]}
            switches["switches"][0]["switch"] = params["switch"]
            switches["switches"][0]["outlet"] = int(self.outlet)
            params = switches

        payload = {
            "sequence": str(
                int(time.time() * 1000)
            ),  # otherwise buffer overflow type issue caused in the device
            "deviceid": device_id,
        }

        if self.encrypted:

            self.logger.debug("params: %s", params)

            sonoffcrypto.format_encryption_msg(payload, self.api_key, params)
            self.logger.debug("encrypted: %s", payload)

        else:
            payload["encrypt"] = False
            payload["data"] = params
            self.logger.debug("message to send (plaintext): %s", payload)

        return payload

    def set_url(self, ip, port):

        socket_text = ip + ":" + port
        self.url = "http://" + socket_text
        self.logger.debug("service is at %s", self.url)

    def create_http_session(self):

        # create an http session so we can use http keep-alives
        self.http_session = requests.Session()

        # add the http headers
        # note the commented out ones are copies from the sniffed ones
        headers = collections.OrderedDict(
            {
                "Content-Type": "application/json;charset=UTF-8",
                # "Connection": "keep-alive",
                "Accept": "application/json",
                "Accept-Language": "en-gb",
                # "Content-Length": "0",
                # "Accept-Encoding": "gzip, deflate",
                # "Cache-Control": "no-store",
            }
        )

        # needed to keep headers in same order
        # instead of self.http_session.headers.update(headers)
        self.http_session.headers = headers

    def set_retries(self, retry_count):

        # no retries at moment, control in sonoffdevice
        retries = Retry(
            total=retry_count,
            backoff_factor=0.5,
            method_whitelist=["POST"],
            status_forcelist=None,
        )

        self.http_session.mount("http://", HTTPAdapter(max_retries=retries))
