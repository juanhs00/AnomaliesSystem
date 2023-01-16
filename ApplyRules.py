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
        
    #GenericRules
    TypeRule()
    BlacklistProcess()
    WhitelistProcess()

    #ANOMALY - CORRELATED
    mobileType = ['6GAnomaly','5GAnomaly','4GAnomaly','3GAnomaly','2GAnomaly']
    AnomaliesToCorrelatedRule(mobileType, 'MobileAnomalies')

    waveType = ['WFAnomaly','RFAnomaly','NFCAnomaly','BTAnomaly','GPSAnomaly']
    AnomaliesToCorrelatedRule(waveType, 'WaveAnomalies')

    wirelessType = ['MobileAnomalies','WaveAnomalies']
    AnomaliesToCorrelatedRule(wirelessType, 'WirelessAnomalies')

    zeroTrafficType = ['ZeroTraffic']
    AnomaliesToCorrelatedRule(zeroTrafficType, 'NetworkIsDead')

    muchTrafficType = ['SaturatedTraffic', 'LoadedTraffic']
    AnomaliesToCorrelatedRule(muchTrafficType, 'NetworkIsSaturated')

    #ANOMALY - THREAT
    AnomalyToThreatRule('GPSAnomaly','NaturalDisasters')
    AnomalyToThreatRule('BTAnomaly','SocialEngineering')
    AnomalyToThreatRule('5GAnomaly','DeviceTheft')
    AnomalyToThreatRule('4GAnomaly','DeviceTheft')
    AnomalyToThreatRule('3GAnomaly','DeviceTheft')
    AnomalyToThreatRule('ZeroTraffic','DeviceLost')
    AnomalyToThreatRule('AccessWithoutEnterpriseVPN','DeviceLost')
    AnomalyToThreatRule('MalwareDetected','SWVulnerabilities')
    AnomalyToThreatRule('MalwareDetected','NonIntentionalInformationLeak')
    AnomalyToThreatRule('MalwareDetected','PrivilegeEscalation')
    AnomalyToThreatRule('IllegalBehaviorDetected','PrivilegeEscalation')
    AnomalyToThreatRule('IllegalBehaviorDetected','ConfigurationError')
    AnomalyToThreatRule('ConnectionLostWithAnyHeadquarters','Fire')
    AnomalyToThreatRule('AccessWithoutEnterpriseVPN','InsiderThreats')
    AnomalyToThreatRule('IPUnknown','SWVulnerabilities')
    AnomalyToThreatRule('AuthenticationError','UnexpectedUsage')
    
    #CORRELATED - THREAT
    CorrelatedToThreatRule('MobileAnomalies','DataMobileAttack')
    CorrelatedToThreatRule('WirelessAnomalies','Fire')
    CorrelatedToThreatRule('NetworkIsDead','Terrorism')
    CorrelatedToThreatRule('NetworkIsSaturated','DenialOfService')
    CorrelatedToThreatRule('NetworkIsSaturated','ConfigurationError')

    #THREAT - RISK
    ThreatToRiskRule('NaturalDisasters','NaturalDisasterRisk')
    ThreatToRiskRule('SocialEngineering','DataProtectionComplianceRisk')
    ThreatToRiskRule('DeviceTheft','DataProtectionComplianceRisk')
    ThreatToRiskRule('DeviceLost','QualityAndProcessRisk')
    ThreatToRiskRule('NonIntentionalInformationLeak','SWMaintenanceErrorRisk')
    ThreatToRiskRule('PrivilegeEscalation','SWMaintenanceErrorRisk')
    ThreatToRiskRule('PrivilegeEscalation','InformationSecurityRisk')
    ThreatToRiskRule('ConfigurationError','DelayedDeliveryRisk')
    ThreatToRiskRule('Fire','HWMaintenanceErrorRisk') 
    ThreatToRiskRule('InsiderThreats','UntrustworthyRisk')
    ThreatToRiskRule('SWVulnerabilities','MonitoringErrorRisk')
    ThreatToRiskRule('Fire','EconomicLossRisk')
    ThreatToRiskRule('DataMobileAttack','StrategicRisk')
    ThreatToRiskRule('UnexpectedUsage','StrategicRisk')
    ThreatToRiskRule('Terrorism','EconomicLossRisk')
    ThreatToRiskRule('DenialOfService','BadReputationRisk')
    ThreatToRiskRule('ConfigurationError','UsersComplaintsRisk')

def ApplyRulesValidation():

        #GenericRules
        TypeRule()
        BlacklistProcess()
        WhitelistProcess()

        #ANOMALY - CORRELATED
        mobileType = ['6GAnomaly','5GAnomaly','4GAnomaly','3GAnomaly','2GAnomaly']
        AnomaliesToCorrelatedRule(mobileType, 'MobileAnomalies')

        zeroTrafficType = ['ZeroTraffic']
        AnomaliesToCorrelatedRule(zeroTrafficType, 'NetworkIsDead')

        #ANOMALY - THREAT
        AnomalyToThreatRule('MalwareDetected','SWVulnerabilities')
        
        #CORRELATED - THREAT
        CorrelatedToThreatRule('MobileAnomalies','DataMobileAttack')
        CorrelatedToThreatRule('NetworkIsDead','Terrorism')

        #THREAT - RISK
        ThreatToRiskRule('SWVulnerabilities','SWMaintenanceErrorRisk')
        ThreatToRiskRule('DataMobileAttack','StrategicRisk')
        ThreatToRiskRule('Terrorism','TerrorismAttackRisk')
        
        