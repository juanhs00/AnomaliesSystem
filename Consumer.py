from kafka import KafkaConsumer,KafkaAdminClient
from owlready2 import *
from ApplyRules import *
import pathlib

#Recibe los individuos creados en tiempor real por productor para introducirlos en la ontología. Además aplica las reglas SPARQL cada 'maxCounter' eventos 
#IMPORTANTE: Activar servidor Kafka introduciendo los siguientes comandos en dos terminales
#/rutaAServerKafka/bin/zookeeper-server-start.sh config/zookeeper.properties
#/rutaAServerKafka/bin/kafka-server-start.sh config/server.properties

counter = 0
maxCounter = 24
path=str(pathlib.Path().absolute())
onto_path.append(path)
onto = get_ontology("System.owl").load()

def CreateLogs():
     #Logs
        path=pathlib.Path().absolute()
        filepath= str(path) + '/logs/ThreatsLog.txt'
        file = open(filepath, "w")
        file.write('Threat, Time, Impact, Anomaly' + os.linesep)
        file.close()

        path=pathlib.Path().absolute()
        filepath= str(path) + '/logs/blacklistAnomaliesLog.txt'
        file = open(filepath, "w")
        file.write('Anomaly, Time' + os.linesep)
        file.close()

        path=pathlib.Path().absolute()
        filepath= str(path) + '/logs/RisksLog.txt'
        file = open(filepath, "w")
        file.write('Risk, Time, RiskValue, Threat'+ os.linesep)
        file.close()

        path=pathlib.Path().absolute()
        filepath= str(path) + '/logs/blacklistRisksLog.txt'
        file = open(filepath, "w")
        file.write('Risk, Time, RiskValue, Threat' + os.linesep)
        file.close()

        path=pathlib.Path().absolute()
        filepath= str(path) + '/logs/CorrelatedAnomaliesLog.txt'
        file = open(filepath, "w")
        file.write('Correlated, Time, Severity, Anomaly' + os.linesep)
        file.close()

        path=pathlib.Path().absolute()
        filepath= str(path) + '/logs/blacklistThreatsLog.txt'
        file = open(filepath, "w")
        file.write('Threat, Time, Impact, Anomaly' + os.linesep)
        file.close()

        path=pathlib.Path().absolute()
        filepath= str(path) + '/logs/ThreatsCorrelatedLog.txt'
        file = open(filepath, "w")
        file.write('Threat, Time, Impact, Correlated' + os.linesep)
        file.close()

        path=pathlib.Path().absolute()
        filepath= str(path) + '/logs/whitelistAnomaliesLog.txt'
        file = open(filepath, "w")
        file.write('Total anomalies' + os.linesep)
        file.close()

with onto:
    class Anomaly(Thing):
        pass
    class Wired(Anomaly):
        pass
    class Wireless(Anomaly):
        pass
    class isType(DataProperty):
        pass
    class hasSeverity(DataProperty):
        pass
    class isBlacklist(DataProperty):
        pass
    class isWhitelist(DataProperty):
        pass
    class hasTime(DataProperty):
        pass

CreateLogs()
admin = KafkaAdminClient(bootstrap_servers=['localhost:9092'])
admin.delete_topics(['quickstart-events'])
consumer = KafkaConsumer(bootstrap_servers=['localhost:9092'], auto_offset_reset='earliest')
consumer.subscribe(['quickstart-events'])

for event in consumer:
    line = str(event)
    line = line.split(' ')[6]
    line = line[9:-3]
    type = line.split(',')[6]
    if type == 'Wired':
        NewA = Wired(line.split(',')[0])
    if type == 'Wireless':
        NewA = Wireless(line.split(',')[0])
    NewA.hasSeverity = int(line.split(',')[1])
    NewA.hasTime =float(line.split(',')[2])
    NewA.isBlacklist = eval(line.split(',')[4])
    NewA.isWhitelist = eval(line.split(',')[3])
    NewA.isType = [str(line.split(',')[5]),'Anomaly']
    NewA.isProcessed = eval(line.split(',')[7])
    NewA.isCorrelated = eval(line.split(',')[8])
    counter = counter + 1

    if counter== maxCounter:
        counter = 0
        if str(line.split(',')[0])[0:1] == 'a':
            ApplyRules()
        if str(line.split(',')[0])[0:1] == 'v':   
            ApplyRulesValidation()