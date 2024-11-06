from typing import Optional

from pydantic import BaseModel


class Conntrack(BaseModel):
    zone: Optional[int] = None
    table: Optional[int] = None
    flags: Optional[int] = None

    class Config:
        frozen = True


class Action(BaseModel):
    allow: Optional[bool] = None
    ct: Optional[Conntrack] = None

    class Config:
        frozen = True


class Rule(BaseModel):
    eth_type: Optional[str] = None
    ip_proto: Optional[int] = None
    vlan_vid: Optional[int] = None
    ipv4_src: Optional[str] = None
    ipv4_dst: Optional[str] = None
    tcp_dst: Optional[int] = None
    tcp_src: Optional[int] = None
    udp_dst: Optional[int] = None
    udp_src: Optional[int] = None
    ct_state: Optional[str] = None
    ct_zone: Optional[int] = None
    actions: Action

    class Config:
        frozen = True


class AclRule(BaseModel):
    rule: Rule

    class Config:
        frozen = True

    # def __eq__(self, other):
    #     if not isinstance(other, AclRule):
    #         return NotImplemented

    #     return self.rule == other.rule


class Acls(BaseModel):
    acls: Optional[dict[str, list[AclRule]]] = None
