#!/usr/bin/env python

import sys

from cobra.mit.session import LoginSession
from cobra.mit.access import MoDirectory
from cobra.mit.request import ConfigRequest, DnQuery

# Import model 
from cobra.model.fvns import VlanInstP, EncapBlk
from cobra.model.infra import RsVlanNs, Infra, AccPortP, AccPortGrp, AccBndlGrp, RsMonIfInfraPol, RsLldpIfPol, RsCdpIfPol, RsL2IfPol, RsAttEntP, RsMcpIfPol, FuncP, RsHIfPol, RsLacpPol, HPortS, RsAccBaseGrp, PortBlk, NodeP, LeafS, NodeBlk, RsAccPortP, AttEntityP, RsDomP
from cobra.model.fv import Tenant, Ctx, BD, RsCtx, Ap, AEPg, RsBd, RsDomAtt, RsPathAtt, Subnet
from cobra.model.vmm import DomP, UsrAccP, CtrlrP, RsAcc, ProvP
from cobra.model.lacp import LagPol
from cobra.model.pol import Uni
from cobra.model.fabric import ProtPol, ExplicitGEp, RsVpcInstPol, NodePEp, Inst, HIfPol
from cobra.model.phys import DomP
import cobra.model.mcp as mcpIfPol
import cobra.model.cdp as cdpIfPol
import cobra.model.lldp as lldpIfPol


import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from cobra.internal.codec.xmlcodec import toXMLStr

def apic_login(host, user, password):
	apicUrl = 'https://%s' % (host)
	moDir = MoDirectory(LoginSession(apicUrl, user, password))
	moDir.login()
	return moDir

def cfg_commit(moDir,object):
	tenantCfg = ConfigRequest()
	tenantCfg.addMo(object)
	moDir.commit(tenantCfg)

def infra_policy(host, user, password):
	moDir = apic_login(host, user, password)
	
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	# Create Link Level Policies for Fabric
	print ('-- Creating Link Level Policies:')
	print ('	10G Interface')
	fabric10GPol = HIfPol(infraInfra, name=u'10GE-SFP-Cobra', fecMode=u'inherit', autoNeg=u'on', speed=u'10G', linkDebounce=u'100')
	print ('	1G Interface')
	fabric1GPol = HIfPol(infraInfra, name=u'1GE-SFP-Cobra', fecMode=u'inherit', autoNeg=u'on', speed=u'1G', linkDebounce=u'100')
	print ('	FE Interface')
	fabricFEPol = HIfPol(infraInfra, name=u'FE-SFP-Cobra', fecMode=u'inherit', autoNeg=u'on', speed=u'100M', linkDebounce=u'100')
	
	# Create CDP Policies for Fabric
	print('--- Creating CDP Policies:')
	print ('	CDP Enabled')
	cdpIfPolEnabled = cdpIfPol.IfPol(infraInfra, name=u'CDP-Enabled-Cobra', adminSt=u'enabled')
	print ('	CDP Disabled')
	cdpIfPolDisabled = cdpIfPol.IfPol(infraInfra, name=u'CDP-Disabled-Cobra', adminSt=u'disabled')
	
	# Create LLDP Policies for Fabric
	print ('--- Creating LLDP Policies:')
	print ('	LLDP Enabled')
	lldpIfPolEnabled = lldpIfPol.IfPol(infraInfra, name=u'LLDP-Enabled-Cobra', adminTxSt=u'enabled', adminRxSt=u'enabled')
	print ('	LLDP Disabled')
	lldpIfPolDisabled = lldpIfPol.IfPol(infraInfra, name=u'LLDP-Disabled-Cobra', adminTxSt=u'disabled', adminRxSt=u'disabled')
	
	# Create LAG Policies for Fabric
	print('--- Creating LAG Policies:')
	print ('	LACP Active')
	lacpLagPolLACP = LagPol(infraInfra, name=u'LACP-Active-Cobra', minLinks=u'1', ctrl=u'fast-sel-hot-stdby,graceful-conv,susp-individual', maxLinks=u'16', mode=u'active')
	print ('	MAC Pinning')
	lacpLagPolMACPIN = LagPol(infraInfra, name=u'MAC-PIN-Cobra', minLinks=u'1', ctrl=u'fast-sel-hot-stdby,graceful-conv,susp-individual', maxLinks=u'16', mode=u'mac-pin')
	
	# Create MCP Policies - disable needed?
	print('--- Creating MCP Policies:')
	print ('	MCP Enabled')
	mcpIfPolEnabled = mcpIfPol.IfPol(infraInfra, name=u'MCP-Enabled-Cobra', descr=u'Enable Mis-Cabling Protocol', adminSt=u'enabled')
	print ('	MDP Disabled')
	mcpIfPolDisabled = mcpIfPol.IfPol(infraInfra, name=u'MCP-Disabled-Cobra', descr=u'Disable Mis-Cabling Protocol', adminSt=u'disabled')
	
	cfg_commit(moDir,infraInfra)
	print('[END] Infrastructure Policies \n')

def vpc_policy(host, user, password):
	print('[BEG] VPC Configuration')
	moDir = apic_login(host, user, password)
	
	polUni = Uni('')
	fabricInst = Inst(polUni)
	
	print('--- Creating VPC Domain')
	
	VPCdID='20'
	SW1='103'
	SW2='104'
	
	fabricProtPol = ProtPol(fabricInst, pairT=u'explicit', name=u'default')
	fabricExplicitGEp = ExplicitGEp(fabricProtPol, id=VPCdID, name=u'VPC-Cobra-Policy')
	fabricRsVpcInstPol = RsVpcInstPol(fabricExplicitGEp, tnVpcInstPolName=u'default')
	print('--- Assigning LEAF Switches - Node'+SW1+' Node'+SW2+' to Domain ID:'+VPCdID)
	fabricNodePEp = NodePEp(fabricExplicitGEp, id=SW1)
	fabricNodePEp2 = NodePEp(fabricExplicitGEp, id=SW2)
	
	tenantCfg = ConfigRequest()
	tenantCfg.addMo(fabricInst)
	moDir.commit(tenantCfg)
	print('[END] VPC Configuration \n')

def if_policyG(host, user, password):
	print ('[BEG] Interface Policy Group Creation')
	moDir = apic_login(host, user, password)

	polUni = Uni('')
	infraInfra = Infra(polUni)
	infraFuncP = FuncP(infraInfra)
	
	ifPG_Name='ASA-Port-Policy-VPC-Cobra'
	lldp_pol='LLDP-Enabled-Cobra'
	cdp_pol='CDP-Enabled-Cobra'
	mcp_pol='MCP-Enabled-Cobra'
	if_pol='1GE-SFP-Cobra'
	lag_pol='LACP-Active-Cobra'
	
	print('--- Creating Policy Group Name: '+ifPG_Name)
	infraAccBndlGrp = AccBndlGrp(infraFuncP, name=ifPG_Name, lagT=u'node')
	
	print ('	Applying LLDP Policy: '+lldp_pol)
	infraRsLldpIfPol = RsLldpIfPol(infraAccBndlGrp, tnLldpIfPolName=lldp_pol)
	
	print ('	Applying CDP Policy: '+cdp_pol)
	infraRsCdpIfPol = RsCdpIfPol(infraAccBndlGrp, tnCdpIfPolName=cdp_pol)
	
	print ('	Applying MCP Policy: '+mcp_pol)
	infraRsMcpIfPol = RsMcpIfPol(infraAccBndlGrp, tnMcpIfPolName=mcp_pol)
	
	print ('	Applying Link Policy: '+if_pol)
	infraRsHIfPol = RsHIfPol(infraAccBndlGrp, tnFabricHIfPolName=if_pol)

	print ('	Applying LAG Policy: '+lag_pol)
	infraRsLacpPol = RsLacpPol(infraAccBndlGrp, tnLacpLagPolName=u'LACP-Active-Cobra')
	
	cfg_commit(moDir,infraFuncP)
	print ('[END] Interface Policy Group Creation \n')
	return ifPG_Name

def int_profile(host, user, password, port_policy):

	print('[BEG] Port Profile Configuration')
	moDir = apic_login(host, user, password)
	
	# Get Top Level Objects
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	# Variables to keep Ports Consistent  
	intPName='ASA-VPC-INT-PROFILE-Cobra'
	pSPortP=port_policy
	pSFexId='101'
	pS1='15'
	pS2='16'
	
	# Port Selector Variables #1 - to be used later for other method of input

	pSName='ASA_VPC_Port_Range_'+pS1+'_to_'+pS2+'-Cobra'

	# Port Selector Variables #2 - to be used later for other method of input
	
	print ('--- Creating Port Profile '+intPName)
	infraAccPortP = AccPortP(infraInfra, name=intPName)
	
	print ('	Adding '+pSName+' to Profile: '+intPName)
	infraHPortS = HPortS(infraAccPortP, type=u'range', name=pSName)
	infraRsAccBaseGrp = RsAccBaseGrp(infraHPortS, fexId=pSFexId, tDn=u'uni/infra/funcprof/accbundle-'+pSPortP)
	infraPortBlk = PortBlk(infraHPortS, name=u'block2', fromPort=pS1, fromCard=u'1', toPort=pS1, toCard=u'1')
	infraPortBlk2 = PortBlk(infraHPortS, name=u'block3', fromPort=pS2, fromCard=u'1', toPort=pS2, toCard=u'1')
	
	cfg_commit(moDir,infraInfra)
	print ('[END] Port Profile Configuration \n')
	return intPName

def switch_profile(host, user, password, if_profile):

	print('[BEG] Switch Profile Configuration')
	moDir = apic_login(host, user, password)
	
	# Get Top Level Objects
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	#Create Variables to be used later
	
	sPName='ASA-VPC-1-Cobra'
	swSelName='L103-104-ASA-VPC'
	LFrom='103'
	LTo='104'
	ifProfName=if_profile
	nodeBlkName='somethingsomethingnodeBlk'
	print('--- Creating Switch Profile: '+sPName)
	infraNodeP = NodeP(infraInfra, ownerKey=u'', name=sPName)
	
	print ('	Adding Switch Selector: '+swSelName+' with Nodes :'+LFrom+','+LTo)
	infraLeafS = LeafS(infraNodeP, ownerKey=u'', type=u'range', name=swSelName)
	infraNodeBlk = NodeBlk(infraLeafS, from_=LFrom, name=nodeBlkName, to_=LTo)
	
	print ('	Adding Interface Selector Profile: '+ifProfName)
	infraRsAccPortP = RsAccPortP(infraNodeP, tDn=u'uni/infra/accportprof-'+ifProfName)
	
	# Commit Configuration
	cfg_commit(moDir,infraInfra)
	print ('[END] Switch Profile Configuration \n')

def vlan_pool(host, user, password):
	print('[BEG] VLAN Pool Creation')
	moDir = apic_login(host, user, password)
	
	# Get Top Level Objects
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	vlanPName='ASA-L3-OUT-STATIC-Cobra'
	vlanMode='static'
	vlanTo='vlan-182'
	vlanFrom='vlan-181'
	
	print ('--- Creating VLAN Pool: '+vlanPName)
	fvnsVlanInstP = VlanInstP(infraInfra, name=vlanPName, allocMode=vlanMode)
	print ('	Adding '+vlanMode+' pool from '+vlanFrom+' to '+vlanTo)
	fvnsEncapBlk = EncapBlk(fvnsVlanInstP, to=vlanTo, from_=vlanFrom, allocMode=vlanMode)
	
	cfg_commit(moDir, infraInfra)
	print('[END] VLAN Pool Creation \n')
	return vlanPName

def phys_dom(host, user, password, vlans):
	print ('[BEG] Physical Domain Configuration')
	moDir = apic_login(host, user, password)

	polUni = Uni('')
	
	phyDomName='ASA-UnMan-Cobra'
	
	physDomP = DomP(polUni, name=phyDomName)
	infraRsVlanNs = RsVlanNs(physDomP, tDn=u'uni/infra/vlanns-['+vlans+']-static')
	
	cfg_commit(moDir, physDomP)
	print ('[END] Physical Domain Configuration \n')
	return phyDomName

def AEP_attach(host, user, password, policy, AEP):
	print ('[BEG] Applying '+AEP+' to Interface Policy: '+policy)
	moDir = apic_login(host, user, password)

	polUni = Uni('')
	infraInfra = Infra(polUni)
	infraFuncP = FuncP(infraInfra)
	
	ifPG_Name='ASA-Port-Policy-VPC-Cobra'
	
	infraAccBndlGrp = AccBndlGrp(infraFuncP, name=ifPG_Name, lagT=u'node')
	infraRsAttEntP = RsAttEntP(infraAccBndlGrp, tDn=u'uni/infra/attentp-'+AEP)
	
	cfg_commit(moDir, infraFuncP)
	print('[END] Successful AEP Attach')

def AEP_build(host, user, profile, domain):
	print ('[BEG] Attached Entity Profile Configuration')
	moDir = apic_login(host, user, password)
	
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	aepName='ASA-L3OUT-Cobra'
	print('--- Creating AEP: '+aepName)
	infraAttEntityP = AttEntityP(infraInfra, name=aepName)
	
	print ('	Associating Domain: '+domain+' to AEP: '+aepName)
	infraRsDomP2 = RsDomP(infraAttEntityP, tDn=u'uni/phys-'+domain+'-1')
	
	cfg_commit(moDir,infraInfra)
	print ('[END] Attached Entity Profile Configuration')
	return aepName

def tenant_policy(host, user, password):
	print('[BEG] Tenant Configuration')
	moDir = apic_login(host, user, password)
	
	uniMo = moDir.lookupByDn('uni')
	
	fvTenantMo = Tenant(uniMo, 'AF_PROG_TEST')

	# Create Private Network
	Ctx(fvTenantMo, "DATACENTER")

	# Create Bridge Domain & Subnets 
	fvBDMo1 = BD(fvTenantMo, "SERVER_BD")
	fvSubnet1 = Subnet(fvBDMo1, name=u'Subnet1', ip=u'106.0.1.1/24', preferred=u'no', virtual=u'no')
	fvSubnet2 = Subnet(fvBDMo1, name=u'Subnet2', ip=u'106.0.2.1/24', preferred=u'no', virtual=u'no')
	
	# Create Bridge Domain & Subnets 
	fvBDMo2 = BD(fvTenantMo, "USER_BD")
	fvSubnet3 = Subnet(fvBDMo2, name=u'Subnet3', ip=u'106.0.3.1/24', preferred=u'no', virtual=u'no')
	fvSubnet4 = Subnet(fvBDMo2, name=u'Subnet4', ip=u'106.0.4.1/24', preferred=u'no', virtual=u'no')

	# Create association to private network
	RsCtx(fvBDMo1, tnFvCtxName="DATACENTER")
	RsCtx(fvBDMo2, tnFvCtxName="DATACENTER")

	# Create Application Profile
	fvApMo = Ap(fvTenantMo, 'ASA')

	fvAEPg1 = AEPg(fvApMo, 'WEB_SERVERS')
	fvAEPgBD1 = RsBd(fvAEPg1, tnFvBDName=u'SERVER_BD')
	
	fvRsPathAtt1 = RsPathAtt(fvAEPg1, tDn=u'topology/pod-1/paths-101/pathep-[eth1/15]', primaryEncap=u'unknown', instrImedcy=u'lazy', mode=u'regular', encap=u'vlan-2005')
	
	fvAEPg2 = AEPg(fvApMo, 'USER_NETS')
	fvAEPgBD1= RsBd(fvAEPg2, tnFvBDName='USER_BD')
	
	fvRsPathAtt2 = RsPathAtt(fvAEPg2, tDn=u'topology/pod-1/paths-101/pathep-[eth1/16]', primaryEncap=u'unknown', instrImedcy=u'lazy', mode=u'regular', encap=u'vlan-2006')
	
	cfg_commit(moDir,fvTenantMo)
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

	host = '10.10.2.21'
	user = 'admin'
	password = 'i6i4Penn'
	
	infra_policy(host, user, password)
	
	vpc_policy(host, user, password)
	
	if_PG = if_policyG(host, user, password)
	
	if_profile = int_profile(host, user, password, if_PG)
	
	sw_profile = switch_profile(host, user, password, if_profile)
	
	vlan_pool = vlan_pool(host, user, password)
	
	AssocDomain = phys_dom(host, user, password, vlan_pool)
	
	aepName = AEP_build(host, user, password, AssocDomain)
	
	AEP_attach(host, user, password, if_PG, aepName)
	
	#tenant_policy(host, user, password)