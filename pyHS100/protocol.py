import json
import socket
import struct
import logging
import requests
from typing import Any, Dict, Union

_LOGGER = logging.getLogger(__name__)

class TPLinkSmartHomeProtocol:
    def query(self, request: Union[str, Dict]) -> Any:
        pass

class TPLinkRemoteProtocol(TPLinkSmartHomeProtocol):
    """
    TODO
    """
    INITIALIZATION_VECTOR = 171
    
    def __init__(self,
                 host: str,
                 terminalUUID: str,
                 token: str,
                 deviceId: str) -> None:
        self._host = host
        self._terminalUUID = terminalUUID
        self._token = token
        self._deviceId = deviceId

    def query(self, request: Union[str, Dict]) -> Any:
        """
        Request information from a TP-Link SmartHome Device and return the
        response.

        :param str host: host name or ip address of the device
        :param int port: port on the device (default: 9999)
        :param request: command to send to the device (can be either dict or
        json string)
        :return:
        """
        if isinstance(request, dict):
            passthroughRequest = json.dumps(request)
        else:
            passthroughRequest = request
        
        requestBody = {
            "method": "passthrough",
            "params": {
                "terminalUUID": self._terminalUUID,
                "token": self._token,
                "deviceId": self._deviceId,
                "requestData": passthroughRequest
            }
        }
        requestText = json.dumps(requestBody)
        
        _LOGGER.debug("> %s", requestText)
        response = requests.post(url = self._host, data = requestText)
        _LOGGER.debug("< %s", response.text)
        
        response.raise_for_status()
        responseBody = response.json()
        if (responseBody["error_code"] != 0):
            raise Exception("Server returned error code: " + str(responseBody["error_code"]))
        
        return json.loads(responseBody["result"]["responseData"])


class TPLinkLocalProtocol(TPLinkSmartHomeProtocol):
    """
    Implementation of the TP-Link Smart Home Protocol
    Encryption/Decryption methods based on the works of
    Lubomir Stroetmann and Tobias Esser
    https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/
    https://github.com/softScheck/tplink-smartplug/
    which are licensed under the Apache License, Version 2.0
    http://www.apache.org/licenses/LICENSE-2.0
    """
    INITIALIZATION_VECTOR = 171
    DEFAULT_PORT = 9999
    DEFAULT_TIMEOUT = 5
    
    def __init__(self,
                 host: str,
                 port: int = DEFAULT_PORT) -> None:
        self._host = host
        self._port = port

    def query(self, request: Union[str, Dict]) -> Any:
        """
        Request information from a TP-Link SmartHome Device and return the
        response.
        :param str host: host name or ip address of the device
        :param int port: port on the device (default: 9999)
        :param request: command to send to the device (can be either dict or
        json string)
        :return:
        """
        if isinstance(request, dict):
            request = json.dumps(request)

        timeout = TPLinkLocalProtocol.DEFAULT_TIMEOUT
        sock = None
        try:
            sock = socket.create_connection((self._host, self._port), timeout)

            _LOGGER.debug("> (%i) %s", len(request), request)
            sock.send(TPLinkLocalProtocol.encrypt(request))

            buffer = bytes()
            # Some devices send responses with a length header of 0 and
            # terminate with a zero size chunk. Others send the length and
            # will hang if we attempt to read more data.
            length = -1
            while True:
                chunk = sock.recv(4096)
                if length == -1:
                    length = struct.unpack(">I", chunk[0:4])[0]
                buffer += chunk
                if (length > 0 and len(buffer) >= length + 4) or not chunk:
                    break

        finally:
            try:
                if sock:
                    sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                # OSX raises OSError when shutdown() gets called on a closed
                # socket. We ignore it here as the data has already been read
                # into the buffer at this point.
                pass

            finally:
                if sock:
                    sock.close()

        response = TPLinkLocalProtocol.decrypt(buffer[4:])
        _LOGGER.debug("< (%i) %s", len(response), response)

        return json.loads(response)

    @staticmethod
    def encrypt(request: str) -> bytearray:
        """
        Encrypt a request for a TP-Link Smart Home Device.
        :param request: plaintext request data
        :return: ciphertext request
        """
        key = TPLinkLocalProtocol.INITIALIZATION_VECTOR

        plainbytes = request.encode()
        buffer = bytearray(struct.pack(">I", len(plainbytes)))

        for plainbyte in plainbytes:
            cipherbyte = key ^ plainbyte
            key = cipherbyte
            buffer.append(cipherbyte)

        return bytes(buffer)

    @staticmethod
    def decrypt(ciphertext: bytes) -> str:
        """
        Decrypt a response of a TP-Link Smart Home Device.
        :param ciphertext: encrypted response data
        :return: plaintext response
        """
        key = TPLinkLocalProtocol.INITIALIZATION_VECTOR
        buffer = []

        for cipherbyte in ciphertext:
            plainbyte = key ^ cipherbyte
            key = cipherbyte
            buffer.append(plainbyte)

        plaintext = bytes(buffer)

        return plaintext.decode()