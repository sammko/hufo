#!/bin/env python3
import logging
import random
from base64 import b64encode
from collections import namedtuple
from typing import List
from urllib.parse import urlunsplit

import click
import click_log
import dotenv
import esprima
import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

LOG = logging.getLogger(__name__)
click_log.basic_config(LOG)

dotenv.load_dotenv()


class HuFoError(Exception):
    pass


class LoginError(HuFoError):
    pass


class PcpListError(HuFoError):
    pass


class PcpListParseError(PcpListError):
    pass


class SetPcpError(HuFoError):
    pass


PcpMapping = namedtuple(
    "PcpMapping",
    [
        "id",
        "internal_ip",
        "internal_port",
        "protocol",
        "required_external_ip",
        "required_external_port",
        "allow_proposal",
        "mode",
        "actual_external_ip",
        "actual_external_port",
        "result_code",
    ],
)


class HuFo:
    def __init__(self, address: str, username: str, password: str):
        self.address = address
        self.username = username
        self.password = password
        self.session = requests.Session()

    def url(self, path):
        return urlunsplit(("http", self.address, path, "", ""))

    def login(self):
        try:
            resp = self.session.post(self.url("/asp/GetRandCount.asp"))
            resp.encoding = "utf-8-sig"
            resp.raise_for_status()
        except RequestException as e:
            raise LoginError(e)
        token = resp.text

        LOG.debug("Acquired token")

        b64password = b64encode(self.password.encode("utf8"))
        data = {
            "UserName": self.username,
            "PassWord": b64password,
            "Language": "english",
            "x.X_HW_Token": token,
        }

        try:
            resp = self.session.post(self.url("/login.cgi"), data)
            resp.raise_for_status()
        except RequestException as e:
            raise LoginError(e)

        if not "Cookie" in self.session.cookies:
            raise LoginError("Did not get cookie. Wrong credentials?")

        LOG.debug("Logged in")
        LOG.debug(self.session.cookies.get("Cookie"))

    @staticmethod
    def _extract_pcplist(pcpresp):
        PREFIX = "var PcpMappingList ="

        mappinglist = None
        for line in pcpresp.splitlines():
            if line.startswith(PREFIX):
                mappinglist = line
                break

        if mappinglist is None:
            raise PcpListParseError("Could not find PcpMappingList line in response")

        try:
            script = esprima.parseScript(mappinglist)
            assert len(script.body) == 1, "Line contains multiple statements"
            stmt = script.body[0]
            assert (
                stmt.type == "VariableDeclaration"
            ), "Line is not variable declaration"
            decls = stmt.declarations
            assert len(decls) == 1, "Line contains multiple declarations"
            decl = decls[0]
            assert (
                decl.id.name == "PcpMappingList"
            ), "Variable 'PcpMappingList' is not declared"
            init = decl.init

            assert (
                init.type == "NewExpression" and init.callee.name == "Array"
            ), "'new' expression of an 'Array' must be assigned"
            args = init.arguments

            mappings = []
            for arg in args:
                if arg.type == "Literal" and arg.raw == "null":
                    continue
                assert (
                    arg.type == "NewExpression"
                    and arg.callee.name == "stPcpMappingList"
                ), "'new' expression of an 'stPcpMappingList' must be present"
                values = []
                for sarg in arg.arguments:
                    assert (
                        sarg.type == "Literal"
                    ), "Only literals can be present in stPcpMappingList"
                    values.append(sarg.value)
                mappings.append(PcpMapping(*values))
        except AssertionError as e:
            raise PcpListParseError("Parse failed: " + e.args[0]) from None

        return mappings

    def get_pcplist(self) -> List[PcpMapping]:
        try:
            resp = self.session.get(self.url("/html/bbsp/common/pcplist.asp"))
            resp.raise_for_status()
        except RequestException as e:
            raise PcpListError(e)
        resp.encoding = "utf-8-sig"

        return self._extract_pcplist(resp.text)

    def set_pcp_mapping(self, mapping: PcpMapping):
        resp = self.session.get(self.url("/html/bbsp/pcp/pcp.asp"))
        resp.raise_for_status()
        bs = BeautifulSoup(resp.content, "html.parser")

        onttoken = bs.find("input", {"id": "onttoken"})["value"]
        LOG.debug("onttoken: %s", onttoken)

        data = {
            "x.InternalAddress": mapping.internal_ip,
            "x.InternalPort": mapping.internal_port,
            "x.Protocol": mapping.protocol,
            "x.RequiredExternalAddress": mapping.required_external_ip,
            "x.RequiredExternalPort": mapping.required_external_port,
            "x.AllowProposal": mapping.allow_proposal,
            "x.X_HW_Token": onttoken,
        }
        params = {
            "x": mapping.id
            # "RequestFile": "html/bbsp/pcp/pcp.asp"
        }

        resp = self.session.post(
            self.url("/html/bbsp/pcp/set.cgi"), params=params, data=data
        )
        resp.raise_for_status()


@click.command()
@click.option(
    "-a",
    "--addr",
    "address",
    required=True,
    envvar="HUFO_HUAWEI_ADDR",
    show_envvar=True,
    help="Address of HTTP interface of Huawei router",
)
@click.option(
    "-u",
    "--username",
    required=True,
    envvar="HUFO_HUAWEI_USERNAME",
    show_envvar=True,
    prompt=True,
    help="Admin username",
)
@click.option(
    "-p",
    "--pass",
    "password",
    required=True,
    envvar="HUFO_HUAWEI_PASS",
    show_envvar=True,
    prompt=True,
    hide_input=True,
    help="Admin password",
)
@click.option(
    "-pi",
    "--ports-in",
    "internal_ports",
    required=True,
    envvar="HUFO_REQ_PORTS_INTERNAL",
    show_envvar=True,
    multiple=True,
    help="Allowed internal ports for PCP mapping. Can be specified multiple times.",
)
@click.option(
    "-pe",
    "--port-ext",
    "external_port",
    required=True,
    envvar="HUFO_REQ_PORT_EXTERNAL",
    show_envvar=True,
    help="Required external port for PCP mapping",
)
@click.option(
    "-ii",
    "--ip-in",
    "internal_ip",
    required=True,
    envvar="HUFO_REQ_IP_INTERNAL",
    show_envvar=True,
    help="Required internal IP address for PCP mapping",
)
@click.option(
    "-n",
    "--attempts",
    "max_attempts",
    default=10,
    envvar="HUFO_ATTEMPTS",
    show_default=True,
    show_envvar=True,
    help="How many times to try to reset PCP mapping before giving up",
)
@click_log.simple_verbosity_option(
    LOG, envvar="HUFO_VERBOSITY", show_envvar=True, show_default=True
)
def hufo(
    address,
    username,
    password,
    internal_ports,
    external_port,
    internal_ip,
    max_attempts,
):
    hufo = HuFo(address, username, password)
    try:
        hufo.login()
    except LoginError as e:
        LOG.error("Failed to log in: %s", e)

    req = {
        "required_external_port": lambda x: x == external_port,
        "internal_ip": lambda x: x == internal_ip,
        "internal_port": lambda x: x in internal_ports,
    }

    attempt = 0
    while True:
        if attempt >= max_attempts:
            LOG.error("Failed after %d attempts", attempt)
            return
        pcps = hufo.get_pcplist()

        for pcp in pcps:
            if all(v(getattr(pcp, k)) for k, v in req.items()):
                break
        else:
            LOG.error("Could not find desired mapping.")
            return

        LOG.debug(pcp)
        if not (
            pcp.result_code == "Success" and pcp.actual_external_port == external_port
        ):
            attempt += 1

            candidates = internal_ports.copy()
            candidates.remove(pcp.internal_port)
            internal_port = random.choice(list(candidates))

            upcp = pcp._replace(
                allow_proposal="1", required_external_ip="", internal_port=internal_port
            )
            hufo.set_pcp_mapping(upcp)
        else:
            break

def main():
    try:
        hufo()
    except HuFoError as e:
        LOG.error("%s", e)

if __name__ == "__main__":
    main()
