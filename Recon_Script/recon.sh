## Rayan Chalise  ##
########################################################################
# Just for personal use but you are free to modify 
#################################################################

#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ -z "$1" ]; then
    echo "${RED}❌ Usage: $0 <domain>${NC}"
    exit 1
fi

echo -e "${CYAN}🔍 Please wait, we are getting the subdomains from Subfinder and Assetfinder...${NC}"subfinder -d $1 -silent | tee subs_asset.txt
assetfinder -subs-only $1 | anew subs_sub.txt

cat subs_*.txt | uniq | sort | tee all_subs.txt
wait

echo -e "${GREEN}✅ Identifying active subdomains with dnsx...${NC}"
cat ./all_subs.txt | dnsx -silent | uniq |tee active_subs.txt

echo -e "${YELLOW}🛡️ Checking for subdomain takeovers with Subzy...${NC}"
subjack -w active_subs.txt -c ~/fingerprints.json -ssl | tee subjacked.txt

echo -e "${CYAN}📸 Taking screenshots of active subdomains...${NC}"
gowitness scan file -f active_subs.txt  --screenshot-fullpage -s ./screenshots

mkdir -p patterns_result
echo -e "${GREEN}🌐 Getting all URLs using ~/go/bin/gau...${NC}"
cat active_subs.txt | ~/go/bin/gau --threads 8 --retries 5 --blacklist jpg,png,gif,svg,ico --mc 200,301,302 | durl |  tee urls.txt
echo -e "${CYAN}🔍 Checking for sensitive URIs...${NC}"
grep -E '/(admin|private|config|secret|login|dashboard|secure|hidden|root|restricted|internal|sensitive|cpanel|phpmyadmin|wp-admin|.htaccess|.env|config.php|webadmin|portal|server-status|server-info|backup|archive|test|staging|debug)' 403url.txt
wait
echo -e "${GREEN}✨ We got some of the URLs -> $(wc -l 403url.txt)${NC}"

echo -e "${YELLOW}🔐 Checking for 403s with httpx...${NC}"
cat 403url.txt | httpx -silent -mc 403,401 | tee active403s.txt

echo -e "${CYAN}🔗 Filtering URLs with dnsx...${NC}"
echo "Filtering URLs with dnsx..."
cat urls.txt | uniq | sort | dnsx -silent | tee patterns_result/final_urls.txt

echo -e "${GREEN}⚙️ Running ~/go/bin/gf patterns...${NC}"
cat urls.txt | ~/go/bin/gf xss > ./patterns_result/xss_urls.txt &
cat urls.txt | ~/go/bin/gf lfi > ./patterns_result/lfi_urls.txt &
cat urls.txt | ~/go/bin/gf redirect > ./patterns_result/redirect_urls.txt &
cat urls.txt | ~/go/bin/gf idor > ./patterns_result/idor_urls.txt &
cat urls.txt | ~/go/bin/gf ssti > ./patterns_result/ssti_urls.txt &
cat urls.txt | ~/go/bin/gf rce > ./patterns_result/rce_urls.txt &
cat urls.txt | ~/go/bin/gf sqli > ./patterns_result/sqli_urls.txt &
cat urls.txt | ~/go/bin/gf img-traversal > ./patterns_result/img-traversal_urls.txt &
cat urls.txt | ~/go/bin/gf interestingparams > ./patterns_result/interestingparams_urls.txt &
cat urls.txt | ~/go/bin/gf interestingsubs > ./patterns_result/intrestingsubs.txt
cat urls.txt | ~/go/bin/gf ssrf > ./patterns_result/ssrf_urls.txt
wait

rm subs_asset.txt subs_sub.txt all_subs.txt urls.txt 403urls.txt

echo -e "${GREEN}🎉 Filtering completed. Check for results in the respective files.${NC}"
