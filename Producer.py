from kafka import KafkaProducer
from datetime import datetime
import random
import time
import json
import csv

#Este fichero produce un flujo continuo de anomalías con propiedades aleatorias
#IMPORTANTE: Activar servidor Kafka introduciendo los siguientes comandos en dos terminales
#/rutaAServerKafka/bin/zookeeper-server-start.sh config/zookeeper.properties
#/rutaAServerKafka/bin/kafka-server-start.sh config/server.properties

validation = True
producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

correlated = 0
processed = 0

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
        whitelist = 0
        blacklist = 0
        blist = random.randint (0,100)
        wlist = random.randint (100,150)
        delay = random.uniform(0, 1)
        time.sleep(delay)
        name = 'a' + str(count)
        severity = random.choices(severities, weights=(0,5,10,20,30,20,10,5,0,0,0), k=1)
        severity = severity[0]
        now = datetime.now()
        stamp =  datetime.timestamp(now)
        if wlist == 50 & blist!=125:
            whitelist = 1
        if blist == 125:
            blacklist = 1
        type = random.choices(types, weights=(75,25), k=1)
        type = type[0]
        if type == 'Wired':
            subtype = wired[random.randint(0,len(wired)-1)]
        if type == 'Wireless':
            subtype = wireless[random.randint(0,len(wireless)-1)]
        
        subtype = str(subtype)[2:-2]

        count  = count + 1
        print(subtype, type)
        individual = name + ',' + str(severity) + ',' + str(stamp) + ',' + str(whitelist) + ',' + str(blacklist) + ',' + subtype + ',' + type +  ',' + str(processed) +  ',' + str(correlated)
        producer.send('quickstart-events', json.dumps(individual).encode('utf-8'))

if validation:
    count = 1
    index = 1
    delay = 0.1
    types = ['MalwareDetected', 'ZeroTraffic','5GAnomaly','4GAnomaly','3GAnomaly']
    severities = [0,1,2,3,4,5,6,7,8,9,10]

    while count<51:
        subtype = 'Anomaly'
        whitelist = 0
        blacklist = 0
        if count%10== 0:
            blacklist =1
        if (count%11 == 0 & count!=90):
            whitelist = 1
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
        index = index +1
        count  = count + 1

        print(subtype, type)
        individual = name + ',' + str(severity) + ',' + str(stamp) + ',' + str(whitelist) + ',' + str(blacklist) + ',' + subtype + ',' + type +  ',' + str(processed) +  ',' + str(correlated)
        producer.send('quickstart-events', json.dumps(individual).encode('utf-8'))
