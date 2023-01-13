from owlready2 import *
import csv
import pathlib

#Lee ficheros con tipos de clases
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

onto = get_ontology("http://www.ontologies.com/ontologies/System.owl")

#Crea Clases y Propiedades
with onto:
    class Anomaly(Thing):
        pass
    class CorrelatedAnomaly(Thing):
        pass
    class Threat(Thing):
        pass
    class Risk(Thing):
        pass
    class Wired(Anomaly):
        pass
    class Wireless(Anomaly):
        pass
    class generate(ObjectProperty, TransitiveProperty):
        pass
    class isCausedBy(ObjectProperty):
        domain    = [CorrelatedAnomaly]
        range     = [Anomaly]
    class isGeneratedBy(ObjectProperty, TransitiveProperty):
        inverse_property = generate
    class hasSeverity(DataProperty, FunctionalProperty):
        pass
    class isType(DataProperty):
        pass
    class isBlacklist(DataProperty, FunctionalProperty):
        pass
    class isWhitelist(DataProperty, FunctionalProperty):
        pass
    class isCorrelated(DataProperty, FunctionalProperty):
        domain    = [Anomaly]
    class isProcessed(DataProperty, FunctionalProperty):
        pass
    class hasImpact(DataProperty, FunctionalProperty):
        domain    = [Threat]
    class hasProbability(DataProperty, FunctionalProperty):
        domain    = [Threat]
    class hasRiskValue(DataProperty, FunctionalProperty):
        domain    = [Risk]
    class hasTime(DataProperty, FunctionalProperty):
        pass
    class startTime(DataProperty, FunctionalProperty):
        domain    = [CorrelatedAnomaly]
    
    #Desune clases entre sí
    AllDisjoint([Risk, Threat, Anomaly, CorrelatedAnomaly])
    AllDisjoint([Wired,Wireless])

    #Relaciona clases mediante las propiedades
    CorrelatedAnomaly.is_a.append(isCausedBy.some(Anomaly))
    Threat.is_a.append(isGeneratedBy.some(Anomaly  or CorrelatedAnomaly))
    Anomaly.is_a.append(generate.some(Threat))
    CorrelatedAnomaly.is_a.append(generate.some(Threat))
    Threat.is_a.append(generate.some(Risk))
    Risk.is_a.append(isGeneratedBy.some(Threat))
    
    #Generamos subclases de amenazas
    for key in threats:
        NewT = types.new_class(key[0], (Threat,))
    
     #Generamos subclases de riesgos
    for key in risks:
        NewR = types.new_class(key[0], (Risk,))
    
     #Generamos subclases de anomalías correladas
    for key in correlatedAnomalies:
        NewCA = types.new_class(key[0], (CorrelatedAnomaly,))
    
     #Generamos subclases de anomalías
     #Anomalías Wired
    for key in wired:
        NewW = types.new_class(key[0], (Wired,))
    #Anomalías Wireless
    for key in wireless:
        NewWL = types.new_class(key[0], (Wireless,))

#Guardar ontología
path=str(pathlib.Path().absolute())
onto.save(file = (path + '/System.owl'), format = "rdfxml")