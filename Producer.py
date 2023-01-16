from kafka import KafkaProducer
from datetime import datetime
import random
import time
import json
import csv
import sys

#Este fichero produce un flujo continuo de anomalías con propiedades aleatorias
#IMPORTANTE: Activar servidor Kafka introduciendo los siguientes comandos en dos terminales
#/rutaAServerKafka/bin/zookeeper-server-start.sh config/zookeeper.properties
#/rutaAServerKafka/bin/kafka-server-start.sh config/server.properties

validation = True
try:
    producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
except Exception:
    print('Apache Kafka no está iniciado')
    sys.exit()

correlated = 0
processed = 0
whitelist = 0
blacklist = 0

with open('lists/wired.txt','r') as f:
    file = csv.reader(f)
    wired=list(file)

with open('lists/wireless.txt','r') as f:
    file = csv.reader(f)
    wireless=list(file)

if not(validation):
    count = 0
    delay = 0.1
    types = ['Wired', 'Wireless']
    severities = [0,1,2,3,4,5,6,7,8,9,10]

    while True:
        subtype = 'Anomaly'
        delay = random.uniform(0, 1)
        time.sleep(delay)
        name = 'a' + str(count)
        severity = random.choices(severities, weights=(0,5,10,20,30,20,10,5,0,0,0), k=1)
        severity = severity[0]
        now = datetime.now()
        stamp =  datetime.timestamp(now)
        type = random.choices(types, weights=(75,25), k=1)
        type = type[0]
        if type == 'Wired':
            subtype = wired[random.randint(0,len(wired)-1)]
        if type == 'Wireless':
            subtype = wireless[random.randint(0,len(wireless)-1)]
        
        subtype = str(subtype)[2:-2]

        count  = count + 1
        print(subtype)
        individual = name + ',' + str(severity) + ',' + str(stamp) + ',' + str(whitelist) + ',' + str(blacklist) + ',' + subtype + ',' + type +  ',' + str(processed) +  ',' + str(correlated)
        producer.send('quickstart-events', json.dumps(individual).encode('utf-8'))

if validation:
    count = 1
    index = 1
    delay = 0.1
    types = ['MalwareDetected', 'ZeroTraffic','5GAnomaly','4GAnomaly','3GAnomaly']
    typeBlacklist = 'BotnetIPRecognized'
    typeWhitelist = 'DataDownloaded'
    severities = [0,1,2,3,4,5,6,7,8,9,10]

    while count<51:
        subtype = 'Anomaly'
        if index == (len(types)+1):
            index = 1
        delay = random.uniform(0, 1)
        time.sleep(delay)
        name = 'v' + str(count)
        severity = random.choices(severities, weights=(0,5,10,20,30,20,10,5,0,0,0), k=1)
        severity = severity[0]
        now = datetime.now()
        stamp =  datetime.timestamp(now)
        subtype = types[index-1]
        if ((index == 1) | (index == 2)):
            type = 'Wired'
        else:
            type = 'Wireless'
        if count%10== 0:
            type = 'Wired'
            subtype = typeBlacklist
        if (count%11 == 0 & count!=90):
            type = 'Wired'
            subtype = typeWhitelist
        index = index +1
        count  = count + 1

        print(subtype)
        individual = name + ',' + str(severity) + ',' + str(stamp) + ',' + str(whitelist) + ',' + str(blacklist) + ',' + subtype + ',' + type +  ',' + str(processed) +  ',' + str(correlated)
        producer.send('quickstart-events', json.dumps(individual).encode('utf-8'))

