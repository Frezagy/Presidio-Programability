#!/usr/bin/env python
#!C:\Python27\python

import cobra.model.cdp as cdpIfPol
import cobra.model.lldp as lldpIfPol
import cobra.model.mcp as mcpIfPol
import requests
import time
import FabricStaging
from random import random
from clint.textui import progress
from cobra.mit.access import MoDirectory
from cobra.mit.request import ConfigRequest
from cobra.mit.request import DnQuery
from cobra.mit.session import LoginSession
from cobra.model.fabric import ProtPol, ExplicitGEp, RsVpcInstPol, NodePEp, Inst, HIfPol
from cobra.model.fv import AEPg
from cobra.model.fv import Ap
from cobra.model.fv import BD
from cobra.model.fv import Ctx
from cobra.model.fv import RsBd
from cobra.model.fv import RsCtx
from cobra.model.fv import RsDomAtt
from cobra.model.fv import RsPathAtt
from cobra.model.fv import Subnet
from cobra.model.fv import Tenant
from cobra.model.fvns import VlanInstP, EncapBlk
from cobra.model.infra import AccBndlGrp
from cobra.model.infra import AccPortGrp
from cobra.model.infra import AccPortP
from cobra.model.infra import AttEntityP
from cobra.model.infra import FuncP
from cobra.model.infra import HPortS
from cobra.model.infra import Infra
from cobra.model.infra import LeafS
from cobra.model.infra import NodeBlk
from cobra.model.infra import NodeP
from cobra.model.infra import PortBlk
from cobra.model.infra import RsAccBaseGrp
from cobra.model.infra import RsAccPortP
from cobra.model.infra import RsAttEntP
from cobra.model.infra import RsCdpIfPol
from cobra.model.infra import RsDomP
from cobra.model.infra import RsHIfPol
from cobra.model.infra import RsL2IfPol
from cobra.model.infra import RsLacpPol
from cobra.model.infra import RsLldpIfPol
from cobra.model.infra import RsMcpIfPol
from cobra.model.infra import RsMonIfInfraPol
from cobra.model.infra import RsVlanNs
from cobra.model.lacp import LagPol
from cobra.model.phys import DomP
from cobra.model.pol import Uni
from cobra.model.vmm import CtrlrP
from cobra.model.vmm import DomP
from cobra.model.vmm import ProvP
from cobra.model.vmm import RsAcc
from cobra.model.vmm import UsrAccP
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def Tenant_List():
	moDir = FabricStaging.apic_login('10.10.2.21', 'admin', 'i6i4Penn')
	tenant_objects = moDir.lookupByClass('fvTenant')
	
	num = 1
	for tenant in tenant_objects:
		name = tenant.name
		print '[%d]  %s' %(num, name)
		num = num+1

Tenant_List()