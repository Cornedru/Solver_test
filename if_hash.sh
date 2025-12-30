#!/bin/bash

echo "=== Looking for cH in debug_turnstile.html ==="

# Look for window._cf_chl_opt.cH
echo -e "\n1. Looking for window._cf_chl_opt.cH pattern:"
grep -oE "window\._cf_chl_opt\.cH\s*=\s*[\"'][^\"']+[\"']" debug_turnstile.html

# Look for .cH= pattern
echo -e "\n2. Looking for .cH= pattern:"
grep -oE "\.cH\s*=\s*[\"'][^\"']{20,}[\"']" debug_turnstile.html | head -5

# Look for "cH": pattern
echo -e "\n3. Looking for \"cH\": pattern:"
grep -oE "[\"']cH[\"']\s*:\s*[\"'][^\"']{20,}[\"']" debug_turnstile.html | head -5

# Look for cH: pattern (minified)
echo -e "\n4. Looking for cH: pattern (minified):"
grep -oE "cH:[\"'][^\"']{20,}[\"']" debug_turnstile.html | head -5

# Show all _cf_chl_opt assignments
echo -e "\n5. All _cf_chl_opt property assignments:"
grep -oE "window\._cf_chl_opt\.\w+\s*=\s*[\"'][^\"']+[\"']" debug_turnstile.html | head -20

# Look for the _cf_chl_opt object itself
echo -e "\n6. Looking for _cf_chl_opt object initialization:"
grep -A 20 "var _cf_chl_opt" debug_turnstile.html | head -30

# If still not found, look for any long alphanumeric strings in the first script
echo -e "\n7. First script tag content (first 2000 chars):"
sed -n '/<script/,/<\/script>/p' debug_turnstile.html | head -c 2000
