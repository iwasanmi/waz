from multiprocessing.forkserver import connect_to_new_process
import pandas as pd
import requests
import json
import sqlite3
import os
"""ips = '192.168.1.190'

url = f"https://{ips}:55000/security/user/authenticate?raw=false"
T_payload = {}
T_headers = {
    'Authorization': 'Basic d2F6dWgtd3VpOndhenVoLXd1aQ=='
    }
T_response = requests.request("GET", url, headers=T_headers, data=T_payload, verify=False)
auth = T_response.json()
newauth = auth['data']
Real_token = newauth['token']

agents_url = f"https://{ips}:55000/agents"
agents_payload = {}
agent_headers = {
    'Authorization': f"Bearer {Real_token}"
    }
response = requests.request(
    "GET", agents_url, headers=agent_headers, data=agents_payload, verify=False)
jsonresponse = response.json()
gents_list = jsonresponse['data']
agents_lists = gents_list['affected_items']
#print (json.dumps(agents_lists, indent=2))
df =pd.DataFrame(agents_lists)


d1 = df.drop('os', axis=1)
d2 = d1.drop('dateAdd', axis=1)
d3 = d2.drop('version', axis=1)
d4 = d3.drop('lastKeepAlive', axis=1)
d5 = d4.drop('node_name', axis=1)
d6 = d5.drop('ip', axis=1)
d7 = d6.drop('registerIP', axis=1)
d8 = d7.drop('manager', axis=1)
d9 = d8.drop('configSum', axis=1)
d10 = d9.drop('mergedSum', axis=1)
d11 = d10.drop('group', axis=1)
d12 = d11.drop('disconnection_time', axis=1)
#d12.to_csv(f'agents.csv', index =False, encoding='utf-8-sig')

conn = sqlite3.connect('agents.db')

c = conn.cursor()



trget_path = './'
def update_csv():
    for files in os.listdir(trget_path):
        if files == 'agents.csv':
            os.remove(files)

    d12.to_csv(f'agents.csv', index =False, encoding='utf-8-sig')
def update_table(table_name):
    #Creating a cursor object using the cursor() method
    cursor = conn.cursor()

    #Doping EMPLOYEE table if already exists
    cursor.execute(f"DROP TABLE {table_name}")
    print("Table dropped... ")
    new_table = f'''create table {table_name}(
    
            status text not null,
            name text not null,
            agentID integer not null
        

            );'''
    cursor.execute(new_table)
    print('new table created')

    #Commit your changes in the database
    conn.commit()

    #Closing the connection
    

def update_db():

    with open('agents.csv', 'r') as csv_files:
        
        records = 0
        for rows in csv_files:
            c.execute(f"INSERT INTO agents VALUES(?, ?, ?)", rows.split(","))
            conn.commit()
            records += 1
            
    conn.close()

update_csv()
update_table('agents')
update_db()

#cnx = sqlite3.connect(':memory:')
#d12.to_sql(name='price2', con=cnx)
#p2 = pd.read_sql('select * from price2 ', cnx)

'''def connect_db():
    sql =sqlite3.connect('agents.db')
    sql.row_factory =sqlite3.Row
    return sql

def get_db():
    if not hasattr(g, 'sqlite3_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()'''
print (d12)
"""

for nfile in os.listdir("./"):
    if nfile.endswith('csv'):
        os.remove(nfile)
from flask import g
def connect_db():
    sql =sqlite3.connect('agents.db')
    sql.row_factory =sqlite3.Row
    return sql

def get_db():
    if not hasattr(g, 'sqlite3_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db
ipad ='192.168.86.244'
url = f"https://{ipad}:55000/security/user/authenticate?raw=false"
T_payload = {}
T_headers = {
    'Authorization': 'Basic d2F6dWgtd3VpOndhenVoLXd1aQ=='
    }
T_response = requests.request("GET", url, headers=T_headers, data=T_payload, verify=False)
auth = T_response.json()
newauth = auth['data']
Real_token = newauth['token']

agents_url = f"https://{ipad}:55000/agents"
agents_payload = {}
agent_headers = {
    'Authorization': f"Bearer {Real_token}"
    }
response = requests.request(
    "GET", agents_url, headers=agent_headers, data=agents_payload, verify=False)
jsonresponse = response.json()
gents_list = jsonresponse['data']
agents_lists = gents_list['affected_items']
hot_fix_payload = {}
hot_fix_headers = {
    'Authorization': f"Bearer {Real_token}"
    }
for ii in agents_lists:
    agt_list = (ii ['id'])
    agt_name = (ii ['name'])
    if agt_list != '000':
        good_list =agt_list
        for t in good_list:
            
        

            json_files = open(f"{agt_name}.json", 'w')
            #json_files.write (str(dict))
            hot_fix_url = f"https://{ipad}:55000/vulnerability/{agt_list}"
            Hot_fix_response = requests.request("GET", hot_fix_url, headers=hot_fix_headers, data=hot_fix_payload, verify=False)
            hot_fix_json = Hot_fix_response.json()
            hot_fx= hot_fix_json ['data']
            #hot = hot_fx ["affected_items"]
            #the_data = json.loads(hotfix_txt  ) 
            hot_fx ['Agent_Name'] = agt_name
            hot_fx ['Agent_ID'] = agt_list
            
            #dict = {"agent_id": {agt_list}, "agent_name": {agt_name}}
            t= hot_fx ['affected_items']
            
            
            
            
            json_files.write(json.dumps(t, indent=2))
            #print(json.dumps(hot_fx, indent=2))
            

            
        json_files.close()

target_path = "./"
for oap in os.listdir(target_path):
    if oap.endswith('.json'):
        FI = open(oap, 'r')
        #FI.close()
        for lines in FI:
            if ('[]') in lines:
                valid_files = oap
                os.remove(valid_files)
          
            else:
                pass
        FI.close() 
    elif oap.endswith('wazuh-server.json'):
        bad = oap
        os.remove(bad)



for eee in os.listdir("./"):
    if eee.endswith("json"):
        ttt= open(eee)
        dataa = json.load(ttt)
        df =pd.DataFrame.from_dict(dataa)
        d1 = df.drop('condition', axis=1)
        d2 = d1.drop('architecture', axis=1)
        d3 = d2.drop('name', axis=1)
        d4 = d3.drop('updated', axis=1)
        d5 = d4.drop('version', axis=1)
        d6 = d5.drop('status', axis=1)
        d7 = d6.drop('external_references', axis=1)
        d8 = d7.drop('type', axis=1)
        d9 = d8.drop('published', axis=1)
        d10 = d9.drop('detection_time', axis=1)
        d11=d10.drop('title', axis=1)
        d12= d11[['cve', 'cvss3_score', 'cvss2_score', 'severity']]
        
        filename = os.path.splitext(eee) [0]
        dicto = [f"{filename}"]
        agent_name = dicto * len(d12)
        d12 ['Agent_name'] =agent_name
        d13 = d12[['Agent_name','cve', 'cvss3_score', 'cvss2_score', 'severity']]
        d13.to_csv(f'{filename}.csv', index =False, encoding='utf-8-sig')
        print (d13)
        
import glob
extension = "csv"
all_files = [i for i in glob.glob('*.{}'.format(extension))]
combined_csv = pd.concat([pd.read_csv(f) for f in all_files])
combined_csv.to_csv('combined.csv', index =False, encoding='utf-8-sig')



def getModifiedPath(originalPath):
    return ''.join(c for c in originalPath if c.isalpha())

for filename in os.listdir(target_path):
    
    if filename.endswith("csv"):
        csv_files = filename
        src = target_path + filename
        dst = target_path + getModifiedPath(filename)
        newname = f"{dst}.csv"
    
        os.rename(src,dst)
        os.rename(dst, newname)




conn = sqlite3.connect('new.db')

c = conn.cursor()

target_path = "./"

for db in os.listdir(target_path):
    if db.endswith(".csv"):
        table_name = db
        real_name = os.path.splitext(table_name) [0]
        print (real_name)
        c.execute(f"""CREATE TABLE if not exists {real_name} (
            Agent_names text,
            Cve text,
            Cvss3_score real,
            Cvss2_score real,
            Severity text
            
              
            )""")
        
        conn.commit()

        with open(db, 'r') as csv_files:
    
            records = 0
            for rows in csv_files:
                c.execute(f"INSERT INTO {real_name} VALUES(?, ?, ?, ?, ?)", rows.split(","))
                conn.commit()
                records += 1
            print('\n{} Records trnsfered'.format(records) )
        
        
conn.close()












"""trget_path = './'

for files in os.listdir(trget_path):
    if files == 'agents.csv':
        os.remove(files)

d12.to_csv(f'agents.csv', index =False, encoding='utf-8-sig')

#Creating a cursor object using the cursor() method
table_name = ('agents')

#Doping EMPLOYEE table if already exists
db = get_db()
db.execute(f"DROP TABLE {table_name}")
print("Table dropped... ")
new_table = f'''create table {table_name}(

        status text not null,
        name text not null,
        agentID integer not null
    

        );'''
db.execute(new_table)
print('new table created')

#Commit your changes in the database
db.commit()

#Closing the connection




with open('agents.csv', 'r') as csv_files:
    
    records = 0
    for rows in csv_files:
        db.execute(f"INSERT INTO agents VALUES(?, ?, ?)", rows.split(","))
        db.commit()
        records += 1"""