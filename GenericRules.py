from owlready2 import *
import csv
from datetime import datetime
import pathlib

path=str(pathlib.Path().absolute())
pathFile= path + '/System.owl'
onto_path.append(path)
onto = get_ontology("System.owl").load()

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

def TypeRule():
    with onto:    
        #Añadimos las anomalías a una subclase en función de su tipo
        for key in wired:
            subtype="""
                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                INSERT { ?w a o:%s.
                         ?w a o:Anomaly.
                        }
                WHERE  {?w a o:Wired.
                        ?w o:isType '%s'}
            """ % (key[0],key[0])
            default_world.sparql(subtype)

        for key in wireless:
            subtype="""
                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                INSERT { ?wl a o:%s.
                         ?wl a o:Anomaly.
                        }
                WHERE  {?wl a o:Wireless.
                        ?wl o:isType '%s'}
            """ % (key[0],key[0])
            default_world.sparql(subtype)

    onto.save(file = pathFile, format = "rdfxml")

def BlacklistProcess():
        
                with onto:                    
                        blackAnomaly = list(default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>

                                SELECT ?a ?ti
                                WHERE { ?a a o:Anomaly
                                        ?a o:hasTime ?ti
                                        ?a o:isBlacklist 1
                                        ?a o:isProcessed 0.
                                }"""))
                        
                path=pathlib.Path().absolute()
                filepath= str(path) + '/logs/blacklistAnomaliesLog.txt'
                file = open(filepath, "a")
                for key in blackAnomaly:
                        blackLog = key
                        file.write(str(blackLog) + os.linesep)
                file.close()

                with onto:
                        default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                INSERT {
                                        ?t o:isGeneratedBy ?a.
                                        ?t o:hasImpact ?s.
                                        ?t o:hasProbability 20.
                                        ?t o:hasTime ?ti.
                                        ?a o:generate ?t.
                                        ?t o:isProcessed 0.
                                        }
                                WHERE { ?a a o:Anomaly
                                        ?a o:isBlacklist 1
                                        ?a o:hasTime ?ti
                                        ?a o:hasSeverity ?s
                                        ?a o:isProcessed 0.
                                BIND(NEWINSTANCEIRI(o:BlacklistThreat) AS ?t)}""")
        
                onto.save(file = pathFile, format = "rdfxml")
                
                with onto:
                        default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                DELETE { ?a o:isProcessed 0.
                                        ?a o:isCorrelated 0.
                                        }
                                INSERT {
                                        ?a o:isProcessed 1.
                                        ?a o:isCorrelated 1.
                                        }
                                WHERE { ?a a o:Anomaly
                                        ?a o:isBlacklist 1
                                        ?a o:isProcessed 0.}""")
                        
                        onto.save(file = pathFile, format = "rdfxml")

                with onto:
                        blackThreat = list (default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                        
                                SELECT ?t ?ti ?s ?a
                                WHERE { ?t a o:BlacklistThreat   
                                        ?t o:hasTime ?ti
                                        ?t o:hasImpact ?s
                                        ?t o:isGeneratedBy ?a
                                        ?t o:isProcessed 0.
                                }"""))
                
                path=pathlib.Path().absolute()
                filepath= str(path) + '/logs/blacklistThreatsLog.txt'
                file = open(filepath, "a")
                for key in blackThreat:
                        blackLog = key
                        file.write(str(blackLog) + os.linesep)
                file.close()
        
                with onto:
                        subtype="""
                                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                                INSERT { ?w a o:Threat.
                                                        }
                                                WHERE  {?w a o:%s.
                                                        ?w o:isProcessed 0}
                                        """ % ('BlacklistThreat')
                        default_world.sparql(subtype)

                onto.save(file = pathFile, format = "rdfxml")
                
                with onto:
                        default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                INSERT {
                                        ?t o:generate ?r.
                                        ?r o:isGeneratedBy ?t.
                                        ?r o:hasRiskValue 0.2.
                                        ?r o:hasTime ?ti.
                                        ?r o:isProcessed 0.
                                        }
                                WHERE { ?t a o:BlacklistThreat   
                                        ?t o:hasTime ?ti
                                        ?t o:hasImpact ?s
                                        ?t o:isProcessed 0.
                                BIND(NEWINSTANCEIRI(o:BlacklistRisk) AS ?r)}""")

                onto.save(file = pathFile, format = "rdfxml")

                with onto:
                        default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                DELETE { ?t o:isProcessed 0.
                                        }
                                INSERT {
                                        ?t o:isProcessed 1.
                                        }
                                WHERE { ?t a o:BlacklistThreat   
                                        ?t o:isProcessed 0.}""")

                onto.save(file = pathFile, format = "rdfxml")
        
                with onto:
                        blackRisk = list (default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                        
                                SELECT ?r ?ti ?s ?t
                                WHERE { ?r a o:BlacklistRisk  
                                        ?r o:hasTime ?ti
                                        ?r o:hasRiskValue ?s
                                        ?r o:isGeneratedBy ?t
                                        ?r o:isProcessed 0.
                                }"""))
                        
                path=pathlib.Path().absolute()
                filepath= str(path) + '/logs/blacklistRisksLog.txt'
                file = open(filepath, "a")
                for key in blackRisk:
                        blackLog = key
                        file.write(str(blackLog) + os.linesep)
                file.close()

                with onto:
                        subtype="""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        INSERT { ?w a o:Risk.
                                                }
                                        WHERE  {?w a o:%s.
                                                ?w o:isProcessed 0}
                                """ % ('BlacklistRisk')
                        default_world.sparql(subtype)

                        default_world.sparql("""
                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                        DELETE { ?r o:isProcessed 0.
                                }
                        INSERT {
                                ?r o:isProcessed 1.
                                }
                        WHERE { ?r a o:BlacklistRisk 
                                ?r o:isProcessed 0.}""")

                onto.save(file = pathFile, format = "rdfxml")

def WhitelistProcess():
                with onto:
                        default_world.sparql("""
                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                DELETE { ?a o:isProcessed 0.
                                        ?a o:isCorrelated 0.  }
                                INSERT { ?a o:isCorrelated 1.
                                        ?a o:isProcessed 1.
                                        }
                                WHERE {
                                        ?a a o:Anomaly
                                        ?a o:isWhitelist 1
                                        ?a o:isProcessed 0.
                                }
                        """)
                
                onto.save(file = pathFile, format = "rdfxml")

                with onto:
                        whiteAnomaly = list(default_world.sparql("""
                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>

                        SELECT (COUNT (?a) AS ?totalA)
                        WHERE { ?a a o:Anomaly
                                ?a o:isProcessed 1
                                ?a o:isCorrelated 1
                                ?a o:isWhitelist 1
                        }"""))
                
                path=pathlib.Path().absolute()
                filepath= str(path) + '/logs/whitelistAnomaliesLog.txt'
                file = open(filepath, "a")
                for key in whiteAnomaly:
                        whiteLog = key
                        file.write(str(whiteLog) + os.linesep)
                file.close()
         

def AnomaliesToCorrelatedRule(anomalyTypes, correlatedType):
                forgetTime = 600
                correlatableAnomalies = 5
                correlatedSeverity = 5
                for key in correlatedAnomalies:
                        if key[0]==correlatedType:
                                correlatedSeverity = int(key[1])
                                forgetTime = int(key[2])
                                correlatableAnomalies = int(key[3])

                now = datetime.now()
                stamp =  datetime.timestamp(now)
                forgetStamp = stamp - forgetTime
                unionMatrix ="""{?a a o:%s.}""" % (anomalyTypes[0])
                index = 0                       
                for key in anomalyTypes:
                        if index != 0:
                                unionMatrix = unionMatrix + """ UNION {?a a o:%s.}""" % (anomalyTypes[index])
                        index = index + 1

                with onto:
                        correlatable = list(default_world.sparql("""
                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                        SELECT ?ti
                        WHERE{ ?a o:isCorrelated 0
                        %s
                        ?a o:hasTime ?ti.
                        FILTER (?ti > %f)}
                        """ % (unionMatrix,forgetStamp)))

                if len(correlatable) >= correlatableAnomalies:
                        hasTime = 0
                        startTime = correlatable[0][0]
                        for key in correlatable:
                                if key[0] > hasTime:
                                        hasTime = key[0]
                                if key[0] < startTime:
                                        startTime = key[0]
                
                        with onto:
                                default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                INSERT {
                                        ?c o:isCausedBy ?a.
                                        ?c o:hasSeverity %d.
                                        ?c o:hasTime %f.
                                        }
                                WHERE { ?a o:isCorrelated 0
                                        %s
                                        ?a o:hasTime %f.
                                BIND(NEWINSTANCEIRI(o:%s) AS ?c)}
                                """ % (correlatedSeverity,hasTime,unionMatrix,hasTime,correlatedType))

                        onto.save(file = pathFile, format = "rdfxml")

                        with onto:
                                default_world.sparql("""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        INSERT { ?c o:isCausedBy ?a.
                                                ?c o:startTime %f.
                                                ?c o:isProcessed 0.
                                                }
                                        WHERE {
                                                ?c a o:%s
                                                ?c o:hasTime %f
                                                ?a o:isCorrelated 0
                                                %s
                                                ?a o:hasTime ?ti.
                                                FILTER (?ti > %f)}
                                """ % (startTime,correlatedType,hasTime,unionMatrix,forgetStamp))

                        onto.save(file = pathFile, format = "rdfxml")

                        with onto:
                                default_world.sparql("""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        DELETE { ?a o:isCorrelated 0}
                                        INSERT { ?a o:isCorrelated 1.
                                                }
                                        WHERE {
                                                %s
                                        }
                                """ % (unionMatrix))

                        onto.save(file = pathFile, format = "rdfxml")

                
                        with onto:
                                correlatedProcess = list(default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                SELECT ?c ?ti ?s ?a
                                WHERE {
                                        ?c a o:%s
                                        ?c o:hasTime %f
                                        ?c o:hasSeverity ?s
                                        %s
                                        ?a o:isCorrelated 1
                                        ?a o:hasTime ?ti.
                                        FILTER (?ti > %f)}
                        """ % (correlatedType,hasTime,unionMatrix,forgetStamp)))

                        path=pathlib.Path().absolute()
                        filepath= str(path) + '/logs/CorrelatedAnomaliesLog.txt'
                        file = open(filepath, "a")
                        for key in correlatedProcess:
                                correlatedLog = key
                                file.write(str(correlatedLog) + os.linesep)
                        file.close()

                        subtype="""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        INSERT { ?w a o:CorrelatedAnomaly.
                                                }
                                        WHERE  {?w a o:%s.
                                                ?w o:isProcessed 0}
                                """ % (correlatedType)
                        with onto:
                                default_world.sparql(subtype)

                        onto.save(file = pathFile, format = "rdfxml")

def AnomalyToThreatRule(anomalyType,threatType):
                threatProbability = 20
                threatImpact = 5
                for key in threats:
                        if key[0]==threatType:
                                threatProbability = int(key[1])
                                threatImpact = int(key[2])

                with onto: 
                        impactProcess = list(default_world.sparql("""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        SELECT  ?ti ?s  
                                        WHERE{  ?a a o:%s.
                                                ?a o:isProcessed 0.
                                                ?a o:hasSeverity ?s.
                                                ?a o:hasTime ?ti
                                        }
                                        """ % (anomalyType)))
                                
                for key in impactProcess:
                        realImpact=int(float(key[1])/10*float(threatImpact))
                        with onto:
                                default_world.sparql("""
                                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                                        INSERT {
                                                                ?a o:generate ?t.
                                                                ?t o:isGeneratedBy ?a.
                                                                ?t o:hasImpact %d.
                                                                ?t o:hasTime %f.
                                                                ?t o:hasProbability %d.
                                                                ?t o:isProcessed 0.
                                                                }
                                                        WHERE  {
                                                                ?a a o:%s.
                                                                ?a o:isProcessed 0.
                                                                ?a o:hasTime %f.
                                                                ?a o:hasSeverity ?s.
                                                        BIND(NEWINSTANCEIRI(o:%s) AS ?t)}
                                                        """ % (realImpact,key[0],threatProbability,anomalyType,key[0],threatType))

                onto.save(file = pathFile, format = "rdfxml")

                subtype="""
                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                        INSERT { ?w a o:Threat.
                                }
                        WHERE  {?w a o:%s.
                                ?w o:isProcessed 0}
                """ % (threatType)

                with onto:
                        default_world.sparql(subtype)

                onto.save(file = pathFile, format = "rdfxml")

                with onto:
                        threatProcess=list(default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                SELECT ?t ?ti ?i ?a
                                WHERE  {?t a o:%s.
                                        ?t o:hasTime ?ti.
                                        ?t o:isProcessed 0
                                        ?t o:hasImpact ?i
                                        ?t o:isGeneratedBy ?a
                                }
                                """ % (threatType)))
                path=pathlib.Path().absolute()
                filepath= str(path) + '/logs/ThreatsLog.txt'
                file = open(filepath, "a")
                for key in threatProcess:
                        threatLog = key
                        file.write(str(threatLog) + os.linesep)
                file.close()

                with onto:
                        default_world.sparql("""
                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                        DELETE { ?a o:isProcessed 0}
                        INSERT {
                                ?a o:isProcessed 1.
                                }
                        WHERE  {?a a o:%s.
                                ?a o:isProcessed 0.}
                        """ % (anomalyType))

                onto.save(file = pathFile, format = "rdfxml")

def CorrelatedToThreatRule(correlatedType,threatType):
                threatProbability = 20
                threatImpact = 5
                for key in threats:
                        if key[0]==threatType:
                                threatProbability = int(key[1])
                                threatImpact = int(key[2])
                with onto: 
                        impactProcess = list(default_world.sparql("""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        SELECT  ?ti ?s  
                                        WHERE{  ?c a o:%s.
                                                ?c o:isProcessed 0.
                                                ?c o:hasSeverity ?s.
                                                ?c o:hasTime ?ti
                                        }
                                        """ % (correlatedType)))
                                
                for key in impactProcess:
                        realImpact=int(float(key[1])/10*float(threatImpact))
                        with onto:
                                default_world.sparql("""
                                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                                        INSERT {
                                                                ?c o:generate ?t.
                                                                ?t o:isGeneratedBy ?c.
                                                                ?t o:hasImpact %d.
                                                                ?t o:hasTime %f.
                                                                ?t o:hasProbability %d.
                                                                ?t o:isProcessed 0.
                                                                }
                                                        WHERE  {
                                                                ?c a o:%s.
                                                                ?c o:isProcessed 0.
                                                                ?c o:hasTime %f.
                                                                ?c o:hasSeverity ?s.
                                                        BIND(NEWINSTANCEIRI(o:%s) AS ?t)}
                                                        """ % (realImpact,key[0],threatProbability,correlatedType,key[0],threatType))

                onto.save(file = pathFile, format = "rdfxml")

                subtype="""
                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                        INSERT { ?w a o:Threat.
                                }
                        WHERE  {?w a o:%s.
                                ?w o:isProcessed 0}
                """ % (threatType)

                with onto:
                        default_world.sparql(subtype)

                onto.save(file = pathFile, format = "rdfxml")

                with onto:
                        threatProcess=list(default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                SELECT ?t ?ti ?i ?c
                                WHERE  {?t a o:%s.
                                        ?t o:hasTime ?ti.
                                        ?t o:hasImpact ?i
                                        ?t o:isProcessed 0.
                                        ?t o:isGeneratedBy ?c
                                }
                                """ % (threatType)))

                path=pathlib.Path().absolute()
                filepath= str(path) + '/logs/ThreatsCorrelatedLog.txt'
                file = open(filepath, "a")
                for key in threatProcess:
                        threatLog = key
                        file.write(str(threatLog) + os.linesep)
                file.close()

                with onto:
                        default_world.sparql("""
                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                        DELETE { ?c o:isProcessed 0}
                        INSERT {
                                ?c o:isProcessed 1.
                                }
                        WHERE  {?c a o:%s.
                                ?c o:isProcessed 0}
                        """ % (correlatedType))

                onto.save(file = pathFile, format = "rdfxml")

def ThreatToRiskRule(threatType,riskType):
                with onto: 
                        valueProcess = list(default_world.sparql("""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        SELECT ?ti ((?p * ?i * .001) AS ?value)   
                                        WHERE{  ?t a o:%s.
                                                ?t o:isProcessed 0.
                                                ?t o:hasProbability ?p.
                                                ?t o:hasImpact ?i.
                                                ?t o:hasTime ?ti
                                        }
                                        """ % (threatType)))
                                
                for key in valueProcess:
                        with onto:
                                default_world.sparql("""
                                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                                        INSERT {
                                                                ?t o:generate ?r.
                                                                ?r o:isGeneratedBy ?t.
                                                                ?r o:hasTime %f.
                                                                ?r o:hasRiskValue %f.
                                                                ?r o:isProcessed 0.
                                                                }
                                                        WHERE  {
                                                                ?t a o:%s.
                                                                ?t o:isProcessed 0.
                                                                ?t o:hasTime %f.
                                                        BIND(NEWINSTANCEIRI(o:%s) AS ?r)}
                                                        """ % (key[0],key[1],threatType,key[0],riskType))

                onto.save(file = pathFile, format = "rdfxml")

                with onto:
                        riskProcess=list(default_world.sparql("""
                                PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                SELECT ?r ?ti ?v ?t
                                WHERE  {?r a o:%s.
                                        ?r o:hasTime ?ti.
                                        ?r o:hasRiskValue ?v
                                        ?r o:isProcessed 0.
                                        ?r o:isGeneratedBy ?t
                                }
                                """ % (riskType)))

                path=pathlib.Path().absolute()
                filepath= str(path) + '/logs/RisksLog.txt'
                file = open(filepath, "a")
                for key in riskProcess:
                        riskLog = key
                        file.write(str(riskLog) + os.linesep)
                file.close()

                with onto:
                        default_world.sparql("""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        DELETE {?t o:isProcessed 0.}
                                                        INSERT {
                                                                ?t o:isProcessed 1.
                                                                }  
                                        WHERE{  ?t a o:%s.
                                                ?t o:isProcessed 0.
                                        }
                                        """ % (threatType))
                
                subtype="""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        INSERT { ?w a o:Risk.
                                                }
                                        WHERE  {?w a o:%s.
                                                ?w o:isProcessed 0}
                                """ % (riskType)

                with onto:
                        default_world.sparql(subtype)

                onto.save(file = pathFile, format = "rdfxml")
        
                with onto:
                        default_world.sparql("""
                                        PREFIX o: <http://www.ontologies.com/ontologies/System.owl#>
                                        DELETE {?r o:isProcessed 0.}
                                                        INSERT {
                                                                ?r o:isProcessed 1.
                                                                }  
                                        WHERE{  ?r a o:%s.
                                                ?r o:isProcessed 0.
                                        }
                                        """ % (riskType))
                
                onto.save(file = pathFile, format = "rdfxml")
