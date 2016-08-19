#!/usr/bin/env python

import sys

import cobra.model.cdp as cdpIfPol
import cobra.model.l3ext as l3ext
import cobra.model.lldp as lldpIfPol
import cobra.model.mcp as mcpIfPol
import requests
import FabricStaging as FS
from cobra.mit.access import MoDirectory
from cobra.mit.request import ConfigRequest, DnQuery
from cobra.mit.session import LoginSession
from cobra.model.fabric import ProtPol, ExplicitGEp, RsVpcInstPol, NodePEp, Inst, HIfPol
from cobra.model.fv import Tenant, Ctx, BD, RsCtx, Ap, AEPg, RsBd, RsDomAtt, RsPathAtt, Subnet, RsProv, RsCons, RsBDToOut
from cobra.model.fvns import VlanInstP, EncapBlk
from cobra.model.infra import RsVlanNs, Infra, AccPortP, AccPortGrp, AccBndlGrp, RsMonIfInfraPol, RsLldpIfPol, RsCdpIfPol, RsL2IfPol, RsAttEntP, RsMcpIfPol, FuncP, RsHIfPol, RsLacpPol, HPortS, RsAccBaseGrp, PortBlk, NodeP, LeafS, NodeBlk, RsAccPortP, AttEntityP, RsDomP
from cobra.model.l3ext import Out, RsEctx, RsNodeL3OutAtt, LIfP, RsPathL3OutAtt, RsL3DomAtt, LNodeP
from cobra.model.l3ext import Subnet as L3Sub
from cobra.model.lacp import LagPol
from cobra.model.ospf import ExtP, IfP, RsIfPol
from cobra.model.phys import DomP
from cobra.model.pol import Uni
from cobra.model.vmm import DomP as vmmDomP
from cobra.model.vmm import UsrAccP, CtrlrP, RsAcc, ProvP
from cobra.model.vz import Filter, Entry, BrCP, Subj, RsSubjFiltAtt
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from cobra.internal.codec.xmlcodec import toXMLStr

TnName ='Cobra-Demo'

def BuildTen(creds,TnName):

	moDir = FS.apic_login(creds[1], creds[2], creds[3])
	uniMo = moDir.lookupByDn('uni')
	fvTenantMo = Tenant(uniMo, TnName)
	try:
		FS.cfg_commit(moDir,fvTenantMo)
		print "Tenant Creation Successful"
	except:
		print "Error with Tenant Creation"

def tenant_policy(host, user, password):
	print('[BEG] Tenant Configuration')
	moDir = FS.apic_login(host, user, password)
	
	uniMo = moDir.lookupByDn('uni')
	
	fvTenantMo = Tenant(uniMo, TnName)

	print('--- Building VRF(s)')
	# Create Private Network
	vrf1 = Ctx(fvTenantMo, "DC_INSIDE")
	vrf2 = Ctx(fvTenantMo, "DC_OUTISDE")

	print('--- Building Bridge Domain(s)')
	# Create Bridge Domain & Subnets 
	fvBDMo1 = BD(fvTenantMo, "SERVER_BD1")
	fvSubnet = Subnet(fvBDMo1, name=u'Sub1', ip=u'106.0.1.1/24', preferred=u'no', virtual=u'no')
	fvSubnet = Subnet(fvBDMo1, name=u'Sub2', ip=u'106.0.2.1/24', preferred=u'no', virtual=u'no')
	
	print('--- Adding Subnets to Bridge Domain(s)')
	# Create Bridge Domain & Subnets 
	fvBDMo2 = BD(fvTenantMo, "SERVER_BD2")
	fvSubnet = Subnet(fvBDMo2, name=u'Sub3', ip=u'106.0.3.1/24', preferred=u'no', virtual=u'no', scope=u'public')
	fvSubnet = Subnet(fvBDMo2, name=u'Sub4', ip=u'106.0.4.1/24', preferred=u'no', virtual=u'yes')
	fvSubnet = Subnet(fvBDMo2, name=u'Sub5', ip=u'106.0.5.1/24', preferred=u'no', virtual=u'no', scope=u'public')

	print('--- Adding Bridge Domain(s) to VRF(s)')
	# Create association to private network
	fv1RsCtx=RsCtx(fvBDMo1, tnFvCtxName=vrf1.name)
	fv2RsCtx=RsCtx(fvBDMo2, tnFvCtxName=vrf1.name)
	
	print('--- Building Web Filter')
	# Build Web Filters
	vzFilter1 = Filter(fvTenantMo, name=u'Web-Filters')
	vzEntry = Entry(vzFilter1, 
					applyToFrag=u'no', 
					dToPort=u'https', 
					prot=u'tcp',  
					stateful=u'no',  
					etherT=u'ip', 
					dFromPort=u'https', 
					name=u'https')
	vzEntry2 = Entry(vzFilter1, 
					applyToFrag=u'no', 
					dToPort=u'https', 
					prot=u'tcp', 
					stateful=u'no', 
					etherT=u'ip', 
					dFromPort=u'https', 
					name=u'https')
					
	print('--- Building App Filter')
	# Build App Filters				
	vzFilter2 = Filter(fvTenantMo, name=u'App-Filters')
	vzEntry = Entry(vzFilter2, 
					applyToFrag=u'no', 
					dToPort=u'8080', 
					prot=u'tcp', 
					stateful=u'no', 
					etherT=u'ip', 
					dFromPort=u'8080', 
					name=u'tcp8080')
	vzEntry2 = Entry(vzFilter2,  
					dToPort=u'8443', 
					prot=u'tcp',  
					stateful=u'no',  
					etherT=u'ip', 
					dFromPort=u'8443', 
					name=u'tcp8443')
	
	print('--- Creating Contract(s)')
	#Create Contracts
	httpContract = BrCP(fvTenantMo, 'WEB')
	vzSubjMo = Subj(httpContract, 'Web-Ports')
	RsSubjFiltAtt(vzSubjMo, tnVzFilterName=vzFilter1.name)
	RsSubjFiltAtt(vzSubjMo, tnVzFilterName='icmp')
	
	appContract = BrCP(fvTenantMo, 'APP')
	vzSubjMo = Subj(appContract, 'App-Ports')
	RsSubjFiltAtt(vzSubjMo, tnVzFilterName=vzFilter2.name)
	RsSubjFiltAtt(vzSubjMo, tnVzFilterName='icmp')
	
	dbContract = BrCP(fvTenantMo, 'DB')
	vzSubjMo = Subj(dbContract, 'DB-Ports')
	RsSubjFiltAtt(vzSubjMo, tnVzFilterName='icmp')
	
	print('--- Creating Application Profile')
	#Create Application Profile
	fvApMo = Ap(fvTenantMo, 'DemoAppProfile')

	print('--- Building EPG: App')
	#Build AEPg APP
	fvAEPg1 = AEPg(fvApMo, 'APP')
	fvAEPgBD1 = RsBd(fvAEPg1, tnFvBDName=fvBDMo1.name)
	#Attach Static AEPg to Interface
	fvRsPathAtt1 = RsPathAtt(fvAEPg1, 
							tDn=u'topology/pod-1/paths-101/pathep-[eth1/15]', 
							primaryEncap=u'unknown', 
							instrImedcy=u'lazy', 
							mode=u'regular', 
							encap=u'vlan-2005')		
							
	AppProv1 = RsProv(fvAEPg1, tnVzBrCPName=appContract.name)
	AppCons1 = RsCons(fvAEPg1, tnVzBrCPName=dbContract.name)	
	
	print('--- Building EPG: Web')
	#Build AEPg WEB
	fvAEPg2 = AEPg(fvApMo, 'WEB')
	fvAEPgBD1= RsBd(fvAEPg2, tnFvBDName=fvBDMo2.name)
	#Attach Static AEPg to Interface
	fvRsPathAtt2 = RsPathAtt(fvAEPg2, 
							tDn=u'topology/pod-1/paths-101/pathep-[eth1/16]', 
							primaryEncap=u'unknown', 
							instrImedcy=u'lazy', 
							mode=u'regular', 
							encap=u'vlan-2006')	
							
	WebProv1 = RsProv(fvAEPg2, tnVzBrCPName=httpContract.name)
	WebCons1 = RsCons(fvAEPg2, tnVzBrCPName=appContract.name)
	
	print('--- Building EPG: DB')
	#Build AEPg DB
	fvAEPg3 = AEPg(fvApMo, 'DB')
	print('	--- Attaching DB to Bridge Domain: '+fvBDMo2.name)
	fvAEPgBD1= RsBd(fvAEPg3, tnFvBDName=fvBDMo2.name)
	#Attach Static AEPg to Interface
	fvRsPathAtt3 = RsPathAtt(fvAEPg3, 
							tDn=u'topology/pod-1/paths-101/pathep-[eth1/17]', 
							primaryEncap=u'unknown', 
							instrImedcy=u'lazy', 
							mode=u'regular', 
							encap=u'vlan-2007')
							
	DbProv1 = RsProv(fvAEPg3, tnVzBrCPName=dbContract.name)
	
	print('--- Building L3 Out')
	# Configure L3 Out
	l3extOut = Out(fvTenantMo, name=u'L3Ext-Cobra', enforceRtctrl=u'export')
	l3extRsEctx = RsEctx(l3extOut, tnFvCtxName=vrf1.name)
	l3extLNodeP = LNodeP(l3extOut, name=u'Leaf102')
	l3extRsNodeL3OutAtt = RsNodeL3OutAtt(l3extLNodeP, rtrIdLoopBack=u'no', rtrId=u'10.10.15.250', tDn=u'topology/pod-1/node-102')
	l3extLIfP = LIfP(l3extLNodeP, name=u'port1-Cobra')
	ospfIfP = IfP(l3extLIfP, authKeyId=u'1')
	ospfRsIfPol = RsIfPol(ospfIfP, tnOspfIfPolName=u'OSPF-P2P')
	l3extRsPathL3OutAtt = RsPathL3OutAtt(l3extLIfP, 
										addr=u'10.10.100.9/30', 
										encapScope=u'local', 
										mode=u'regular',
										ifInstT=u'l3-port', 
										mtu=u'1500', 
										tDn=u'topology/pod-1/paths-102/pathep-[eth1/1]')
										
	l3extInstP = l3ext.InstP(l3extOut, name=u'L3-OUT-EPG')
	fvRsCons = RsCons(l3extInstP, tnVzBrCPName=httpContract.name)
	l3extSubnet = L3Sub(l3extInstP, ip=u'0.0.0.0/0')
	ospfExtP = ExtP(l3extOut, areaCtrl=u'redistribute,summary', areaId=u'0.0.0.1', areaType=u'regular', areaCost=u'1')
	BDAttL3Out1 = RsBDToOut(fvBDMo2, tnL3extOutName=l3extOut.name)

	FS.cfg_commit(moDir,fvTenantMo)
	print('[END] Tenant Configuration')

if __name__ == '__main__':
	#from argparse import ArgumentParser
	#parser = ArgumentParser("Tenant creation script")
	#parser.add_argument('-d', '--host', help='APIC host name or IP',
	#					required=True)
	#parser.add_argument('-p', '--password', help='user password',
	#					required=True)
	#parser.add_argument('-u', '--user', help='user name', required=True)
	#args = parser.parse_args()

	tenant_policy(host, user, password)