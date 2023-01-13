from GenericRules import *
import csv
import pathlib

with open('lists/threats.txt','r') as f:
        file = csv.reader(f)
        threats=list(file)

with open('lists/correlatedAnomalies.txt','r') as f:
        file = csv.reader(f)
        correlatedAnomalies=list(file)

with open('lists/risks.txt','r') as f:
        file = csv.reader(f)
        risks=list(file)

with open('lists/wired.txt','r') as f:
        file = csv.reader(f)
        wired=list(file)

with open('lists/wireless.txt','r') as f:
        file = csv.reader(f)
        wireless=list(file)

def ApplyRules():
    #Parameters
    forgetTime=600
    correlatableAnomalies=20
    validation = False
    
    #GenericRules
    TypeRule()
    BlacklistProcess(validation)
    WhitelistProcess(validation)

    #ANOMALY - CORRELATED
    mobileType = ['6GAnomaly','5GAnomaly','4GAnomaly','3GAnomaly','2GAnomaly']
    AnomaliesToCorrelatedRule(mobileType, 'MobileAnomalies', 9,forgetTime, correlatableAnomalies, validation)

    waveType = ['WFAnomaly','RFAnomaly','NFCAnomaly','BTAnomaly','GPSAnomaly']
    AnomaliesToCorrelatedRule(waveType, 'WaveAnomalies', 9,forgetTime, correlatableAnomalies, validation)

    wirelessType = ['MobileAnomalies','WaveAnomalies']
    AnomaliesToCorrelatedRule(wirelessType, 'WirelessAnomalies', 10, forgetTime*5, 2, validation)

    zeroTrafficType = ['ZeroTraffic']
    AnomaliesToCorrelatedRule(zeroTrafficType, 'NetworkIsDead', 10, forgetTime/2, correlatableAnomalies*2, validation)

    muchTrafficType = ['SaturatedTraffic', 'LoadedTraffic']
    AnomaliesToCorrelatedRule(muchTrafficType, 'NetworkIsSaturated', 9, forgetTime/2, correlatableAnomalies*2, validation)

    #ANOMALY - THREAT
    AnomalyToThreatRule('GPSAnomaly','NaturalDisasters',1, validation)
    AnomalyToThreatRule('BTAnomaly','SocialEngineering',5, validation)
    AnomalyToThreatRule('5GAnomaly','DeviceTheft',5, validation)
    AnomalyToThreatRule('4GAnomaly','DeviceTheft',5, validation)
    AnomalyToThreatRule('3GAnomaly','DeviceTheft',5, validation)
    AnomalyToThreatRule('ZeroTraffic','DeviceLost',5, validation)
    AnomalyToThreatRule('AccessWithoutEnterpriseVPN','DeviceLost',5, validation)
    AnomalyToThreatRule('MalwareDetected','SWVulnerabilities',50, validation)
    AnomalyToThreatRule('MalwareDetected','NonIntentionalInformationLeak',20, validation)
    AnomalyToThreatRule('MalwareDetected','PrivilegeEscalation',20, validation)
    AnomalyToThreatRule('IllegalBehaviorDetected','PrivilegeEscalation',20, validation)
    AnomalyToThreatRule('IllegalBehaviorDetected','ConfigurationError',30, validation)
    AnomalyToThreatRule('ConnectionLostWithAnyHeadquarters','Fire',2, validation)
    AnomalyToThreatRule('AccessWithoutEnterpriseVPN','InsiderThreats',5, validation)
    AnomalyToThreatRule('IPUnknown','SWVulnerabilities',5, validation)
    AnomalyToThreatRule('AuthenticationError','UnexpectedUsage',75, validation)
    
    #CORRELATED - THREAT
    CorrelatedToThreatRule('MobileAnomalies','DataMobileAttack',10, validation)
    CorrelatedToThreatRule('WirelessAnomalies','Fire',20, validation)
    CorrelatedToThreatRule('NetworkIsDead','Terrorism',10, validation)
    CorrelatedToThreatRule('NetworkIsSaturated','DenialOfService',40, validation)
    CorrelatedToThreatRule('NetworkIsSaturated','ConfigurationError',5, validation)

    #THREAT - RISK
    ThreatToRiskRule('NaturalDisasters','NaturalDisasterRisk', validation)
    ThreatToRiskRule('SocialEngineering','DataProtectionComplianceRisk', validation)
    ThreatToRiskRule('DeviceTheft','DataProtectionComplianceRisk',validation)
    ThreatToRiskRule('DeviceLost','Quality&ProcessRisk', validation)
    ThreatToRiskRule('NonIntentionalInformationLeak','SWMaintenanceErrorRisk', validation)
    ThreatToRiskRule('PrivilegeEscalation','SWMaintenanceErrorRisk', validation)
    ThreatToRiskRule('PrivilegeEscalation','InformationSecurityRisk', validation)
    ThreatToRiskRule('ConfigurationError','DelayedDeliveryRisk', validation)
    ThreatToRiskRule('Fire','HWMaintenanceErrorRisk', validation) 
    ThreatToRiskRule('InsiderThreats','UntrustworthyRisk', validation)
    ThreatToRiskRule('SWVulnerabilities','MonitoringErrorRisk', validation)
    ThreatToRiskRule('Fire','EconomicLossRisk', validation)
    ThreatToRiskRule('DataMobileAttack','StrategicRisk', validation)
    ThreatToRiskRule('UnexpectedUsage','StrategicRisk', validation)
    ThreatToRiskRule('Terrorism','EconomicLossRisk', validation)
    ThreatToRiskRule('DenialOfService','BadReputationRisk', validation)
    ThreatToRiskRule('ConfigurationError','UsersComplaintsRisk', validation)

def ApplyRulesValidation():

        #Parameters
        forgetTime=600 #Seconds
        correlatableAnomalies=5
        validation = True
        
        #GenericRules
        TypeRule()
        BlacklistProcess(validation)
        WhitelistProcess(validation)

        #ANOMALY - CORRELATED
        mobileType = ['6GAnomaly','5GAnomaly','4GAnomaly','3GAnomaly','2GAnomaly']
        AnomaliesToCorrelatedRule(mobileType, 'MobileAnomalies', 9,forgetTime, correlatableAnomalies, validation)

        zeroTrafficType = ['ZeroTraffic']
        AnomaliesToCorrelatedRule(zeroTrafficType, 'NetworkIsDead', 10, forgetTime/2, correlatableAnomalies-2, validation)

        #ANOMALY - THREAT
        AnomalyToThreatRule('MalwareDetected','SWVulnerabilities',50, validation)
        
        #CORRELATED - THREAT
        CorrelatedToThreatRule('MobileAnomalies','DataMobileAttack',10, validation)
        CorrelatedToThreatRule('NetworkIsDead','Terrorism',10, validation)

        #THREAT - RISK
        ThreatToRiskRule('SWVulnerabilities','SWMaintenanceErrorRisk', validation)
        ThreatToRiskRule('DataMobileAttack','StrategicRisk', validation)
        ThreatToRiskRule('Terrorism','TerrorismAttackRisk', validation)
        
        