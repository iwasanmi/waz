
from crypt import methods
from flask import Blueprint, render_template, redirect, url_for, request, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user
from __init__ import db
import requests
import glob
import pandas as pd
import sqlite3
import os
import json
from bs4 import BeautifulSoup

import datetime
import json

import re
auth = Blueprint('auth', __name__) 

def connect_db():
    sql =sqlite3.connect('agents.db')
    sql.row_factory =sqlite3.Row
    return sql

def get_db():
    if not hasattr(g, 'sqlite3_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@auth.teardown_app_request
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

@auth.route('/login', methods=['GET', 'POST']) # define login page path
def login(): # define login page fucntion
    if request.method=='GET': 
        return render_template('login.html')
    else: 
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user:
            flash('Please sign up before!')
            return redirect(url_for('auth.signup'))
        elif not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page
        # if the above check passes, then we know the user has the right credentials
        login_user(user, remember=remember)
        return redirect(url_for('main.profile'))

@auth.route('/signup', methods=['GET', 'POST'])# we define the sign up path
def signup(): # define the sign up function
    if request.method=='GET': # If the request is GET we return the sign up page and forms
        return render_template('signup.html')
    else: # if the request is POST, then we check if the email doesn't already exist and then we save data
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database
        if user: # if a user is found, we want to redirect back to signup page so user can try again
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))
        # create a new user with the form data. Hash the password so the plaintext version isn't saved.
        new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256')) #
        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        dd = get_db()
        default_ip = '0.0.0.0'
        the_name = request.form['name']
        dd.execute('insert into server (user, ip) values (?, ?)', [the_name, default_ip])
        dd.commit()
        return redirect(url_for('auth.login'))

@auth.route('/logout') # define logout path
@login_required
def logout(): #define the logout function
    logout_user()
    return redirect(url_for('main.index'))


@auth.route('/setup', methods=['GET', 'POST']) # profile page that return 'profile'
@login_required
def setup():
    db =get_db()
    
    if request.method =='POST':
        name = current_user.name
        ip = request.form['ipaddr']
        
            
        db.execute(f'update server set ip = ? where user = ?', [ip, name])
        db.commit()
        #db.execute('drop table CVES')
        #db.commit()
        
        return redirect(url_for('auth.patch'))

    else:
        return render_template('setup.html', name=current_user.name)


@auth.route('/patch', methods= ['POST', 'GET']) # profile page that return 'profile'
@login_required
def patch():
    db = get_db()
    
        
    if request.method == 'GET':
        user_ip = db.execute ('select * from server where user = ?', [current_user.name])
        the_ip = user_ip.fetchone()
        in_db = user_ip.fetchall ()
        
        
       
        return render_template('patch.html',  name=current_user.name, the_ip = the_ip ['ip'])
    else:
        ip_addr = db.execute ('select * from server where user = ?', [current_user.name])
        ip_adr = ip_addr.fetchone()
        user_ip = db.execute ('select * from server where user = ?', [current_user.name])
        the_ip = user_ip.fetchone()

        

        
        

        


        url = f"https://{ip_adr['ip']}:55000/security/user/authenticate?raw=false"
        T_payload = {}
        T_headers = {
            'Authorization': 'Basic d2F6dWgtd3VpOndhenVoLXd1aQ=='
            }
        T_response = requests.request("GET", url, headers=T_headers, data=T_payload, verify=False)
        auth = T_response.json()
        newauth = auth['data']
        Real_token = newauth['token']

        agents_url = f"https://{ip_adr['ip']}:55000/agents"
        agents_payload = {}
        agent_headers = {
            'Authorization': f"Bearer {Real_token}"
            }
        response = requests.request(
            "GET", agents_url, headers=agent_headers, data=agents_payload, verify=False)
        jsonresponse = response.json()
        gents_list = jsonresponse['data']
        agents_lists = gents_list['affected_items']


    

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
        #d13 = d12.to_dict()
        #cnx = sqlite3.connect(':memory:')
        #t= d12.to_sql(name='price2', con=cnx)
        #p2 = pd.read_sql('select * from price2', cnx)
        



        trget_path = './'

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
                records += 1

        cur = db.execute('select * from agents where rowid != 1')
        p4 = cur.fetchall()
        agents_number = len(p4)




        if request.method == 'GET':
        
        
            return render_template('patch.html',  name=current_user.name)
    
        else:
           

            for nfile in os.listdir("./"):
                if nfile.endswith('csv'):
                    os.remove(nfile)


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
                for ag in agt_list:
                    

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
            for tr in os.listdir("./"):
                if tr.endswith('zuh-server.json'):
                    bad = tr
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
                    print (d10)
                    
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






            target_path = "./"
            
            
            
            db.execute(f"""CREATE TABLE if not exists CVES (
                Agent_names text,
                Cve text,
                Cvss3_score real,
                Cvss2_score real,
                Severity text,
                UNIQUE (Cve)
                
                
                
                
                )""")
            
            db.commit()

            with open('combinedcsv.csv', 'r') as csv_files:
                
                
                

                records = 0
                for rows in csv_files:
                  

                    
                   
                        
                    db.execute(f"INSERT OR IGNORE INTO CVES VALUES(?, ?, ?, ?, ?)", rows.split(","))
                    db.commit()
                    records += 1
                    
                print('\n{} Records trnsfered'.format(records) )
            
            
               

            cur = db.execute('select * from CVES where rowid != 1')  
            
            p3 = cur.fetchall()
            cve_number = len(p3)


            for nfile in os.listdir("./"):
                if nfile.endswith('csv'):
                    os.remove(nfile)


          

            return render_template('patch.html', cve = p3, ip =p4, name=current_user.name, the_ip = the_ip ['ip'], agentnumber=agents_number, cvenumber =cve_number)
        
    

@auth.route('/showDB', methods=['GET', 'POST']) # profile page that return 'profile'
@login_required
def filter_patches():
    db=get_db()
    
   
    #cur =db.execute("select * from CVES where severity like 'M%'")
    low = db.execute("select * from CVES where severity like 'L%'")
    lowf = low.fetchall()
    lowl = len(lowf)

    med = db.execute("select * from CVES where severity like 'M%'")
    medi = med.fetchall()
    mediu = len(medi)

    hi = db.execute("select * from CVES where severity like 'H%'")
    hig = hi.fetchall()
    higg= len(hig)

    cr = db.execute("select * from CVES where severity like 'C%'")
    cri = cr.fetchall()
    crit= len(cri)
    


    cur = db.execute('select * from CVES where rowid != 1')  
            
    p3 = cur.fetchall()
    curr = db.execute('select * from agents where rowid != 1')
    p4 = curr.fetchall()
    user_ip = db.execute ('select * from server where user = ?', [current_user.name])
    the_ip = user_ip.fetchone()

    
    return render_template('ipatched.html', cve = p3, ip =p4, name=current_user.name, the_ip = the_ip ['ip'], low =lowl, medium=mediu, high = higg, critical=crit)


@auth.route('/low', methods=['GET', 'POST']) # profile page that return 'profile'
@login_required
def low():
    db=get_db()
    
   
    #cur =db.execute("select * from CVES where severity like 'M%'")
    low = db.execute("select * from CVES where severity like 'L%'")
    lowf = low.fetchall()
    lowl = len(lowf)
    
    

    med = db.execute("select * from CVES where severity like 'M%'")
    medi = med.fetchall()
    mediu = len(medi)

    hi = db.execute("select * from CVES where severity like 'H%'")
    hig = hi.fetchall()
    higg= len(hig)

    cr = db.execute("select * from CVES where severity like 'C%'")
    cri = cr.fetchall()
    crit= len(cri)
    


    cur = db.execute('select * from CVES where rowid != 1')  
            
    p3 = cur.fetchall()
    curr = db.execute('select * from agents where rowid != 1')
    p4 = curr.fetchall()
    user_ip = db.execute ('select * from server where user = ?', [current_user.name])
    the_ip = user_ip.fetchone()

    
    return render_template('low.html', cve = p3, ip =p4, name=current_user.name, the_ip = the_ip ['ip'], low =lowl, medium=mediu, high = higg, critical=crit, tlow = lowf)




@auth.route('/medium', methods=['GET', 'POST']) # profile page that return 'profile'
@login_required
def medium():
    db=get_db()
    
   
    #cur =db.execute("select * from CVES where severity like 'M%'")
    low = db.execute("select * from CVES where severity like 'L%'")
    lowf = low.fetchall()
    lowl = len(lowf)
    
    

    med = db.execute("select * from CVES where severity like 'M%'")
    medi = med.fetchall()
    mediu = len(medi)

    hi = db.execute("select * from CVES where severity like 'H%'")
    hig = hi.fetchall()
    higg= len(hig)

    cr = db.execute("select * from CVES where severity like 'C%'")
    cri = cr.fetchall()
    crit= len(cri)
    


    cur = db.execute('select * from CVES where rowid != 1')  
            
    p3 = cur.fetchall()
    curr = db.execute('select * from agents where rowid != 1')
    p4 = curr.fetchall()
    user_ip = db.execute ('select * from server where user = ?', [current_user.name])
    the_ip = user_ip.fetchone()

    
    return render_template('medium.html', cve = p3, ip =p4, name=current_user.name, the_ip = the_ip ['ip'], low =lowl, medium=mediu, high = higg, critical=crit, tmedium = medi)



@auth.route('/high', methods=['GET', 'POST']) # profile page that return 'profile'
@login_required
def high():
    db=get_db()
    
   
    #cur =db.execute("select * from CVES where severity like 'M%'")
    low = db.execute("select * from CVES where severity like 'L%'")
    lowf = low.fetchall()
    lowl = len(lowf)
    
    

    med = db.execute("select * from CVES where severity like 'M%'")
    medi = med.fetchall()
    mediu = len(medi)

    hi = db.execute("select * from CVES where severity like 'H%'")
    hig = hi.fetchall()
    higg= len(hig)

    cr = db.execute("select * from CVES where severity like 'C%'")
    cri = cr.fetchall()
    crit= len(cri)
    


    cur = db.execute('select * from CVES where rowid != 1')  
            
    p3 = cur.fetchall()
    curr = db.execute('select * from agents where rowid != 1')
    p4 = curr.fetchall()
    user_ip = db.execute ('select * from server where user = ?', [current_user.name])
    the_ip = user_ip.fetchone()

    
    return render_template('high.html', cve = p3, ip =p4, name=current_user.name, the_ip = the_ip ['ip'], low =lowl, medium=mediu, high = higg, critical=crit, thigh = hig)


@auth.route('/critical', methods=['GET', 'POST']) # profile page that return 'profile'
@login_required
def critical():
    db=get_db()
    
   
    #cur =db.execute("select * from CVES where severity like 'M%'")
    low = db.execute("select * from CVES where severity like 'L%'")
    lowf = low.fetchall()
    lowl = len(lowf)
    
    

    med = db.execute("select * from CVES where severity like 'M%'")
    medi = med.fetchall()
    mediu = len(medi)

    hi = db.execute("select * from CVES where severity like 'H%'")
    hig = hi.fetchall()
    higg= len(hig)

    cr = db.execute("select * from CVES where severity like 'C%'")
    cri = cr.fetchall()
    crit= len(cri)
    


    cur = db.execute('select * from CVES where rowid != 1')  
            
    p3 = cur.fetchall()
    curr = db.execute('select * from agents where rowid != 1')
    p4 = curr.fetchall()
    user_ip = db.execute ('select * from server where user = ?', [current_user.name])
    the_ip = user_ip.fetchone()

    
    return render_template('critical.html', cve = p3, ip =p4, name=current_user.name, the_ip = the_ip ['ip'], low =lowl, medium=mediu, high = higg, critical=crit, tcritical = cri)



@auth.route('/readmore/<cve>', methods=['GET', 'POST']) # profile page that return 'profile'
@login_required
def readmore(cve):
    db=get_db()
    

    html_text = requests.get(f'https://www.cvedetails.com/cve/{cve}/?q={cve}').text

    soup = BeautifulSoup(html_text, 'lxml')
    name = soup.find_all('td', id= "cvedetails")
    for x in name:
        cve_name = x.h1.text.split()[-1]

    description = soup.find('div', class_="cvedetailssummary")
    c =description.text

    sentence = re.sub(r"^\s+", "", c, flags=re.UNICODE)
    cve_description =sentence
    

    cvss_score =soup.find('table', id="cvssscorestable")
    
        

    affected_products = soup.find_all('table', id="vulnprodstable")
    for t in affected_products:
        vulnerability_details = t



    

    base_url = "https://api.msrc.microsoft.com/"
    api_key = "x"

    #Find the cvrf_id (in the form YYYY-Month) given the CVE of interest
    def get_cvrf_id_for_cve(cvt):
        url = "{}Updates('{}')?api-version={}".format(base_url, str(cvt),   str(datetime.datetime.now().year))
        headers = {'api-key': api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = json.loads(response.content)
            id = data["value"][0]["ID"]
        else:
            id = None
        return id

    #get the cvrf data and extract kd's for the CVE of interest
    def get_knowledge_bases_for_cve(cvt):
        id = get_cvrf_id_for_cve(cvt)
        if id == None:
            return []
        url = "{}cvrf/{}?api-Version={}".format(base_url, id,   str(datetime.datetime.now().year))
        headers = {'api-key': api_key, 'Accept': 'application/json'}
        response = requests.get(url, headers = headers)
        data = json.loads(response.content)
        kbs = {'KB{}'.format(kb['Description']['Value']) for vuln in data["Vulnerability"] if vuln["CVE"] == cvt for kb in vuln["Remediations"]}
        return kbs

    eternal_blue = cve
    eternal_blue_kbs = get_knowledge_bases_for_cve(eternal_blue)
    kbss =[]
    for x in eternal_blue_kbs:
        
        if " " not in x:
            kbss.append(x)

    kbi = kbss
    #print(str(datetime.datetime.now().year))




        
        
    

        
    
   



    
    return render_template('find.html', cve=cve, c=c, cve_name=cve_name, kb=kbi)




@auth.route('/search', methods= ['POST', 'GET'])
def search():
    if request.method == 'GET':
        
        
        return render_template('patch.html',  name=current_user.name)
    
    else:

        for nfile in os.listdir("./"):
            if nfile.endswith('csv'):
                os.remove(nfile)


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
            for ag in agt_list:
                

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
                print (d10)
                
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






        target_path = "./"
        db =get_db()
        
        
        db.execute(f"""CREATE TABLE if not exists CVES (
            Agent_names text,
            Cve text,
            Cvss3_score real,
            Cvss2_score real,
            Severity text
            
            
            )""")
        
        db.commit()

        with open('combinedcsv.csv', 'r') as csv_files:

            records = 0
            for rows in csv_files:
                db.execute(f"INSERT INTO CVES VALUES(?, ?, ?, ?, ?)", rows.split(","))
                db.commit()
                records += 1
            print('\n{} Records trnsfered'.format(records) )
                
        cur = db.execute('select * from CVES where rowid != 1')  
        
        p3 = cur.fetchall()


        for nfile in os.listdir("./"):
            if nfile.endswith('csv'):
                os.remove(nfile)
        return render_template('ipatched.html', cve = p3)
        
        
