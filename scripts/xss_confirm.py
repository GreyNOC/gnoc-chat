#!/usr/bin/env python3
"""Reusable runtime XSS confirmation harness (Selenium + CDP).
Usage: xss_confirm.py "<url-with-payload>" [hash_payload]
Hooks alert/prompt/confirm + onerror sentinel. Reports execution + raw-DOM presence.
The payload should embed the sentinel ZQX9 so we can locate context.
Captures: did dialog fire (terminal receipt), did sentinel reach DOM raw as a TAG.
"""
import sys, time, json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

SENT="ZQX9"
HOOK=f"""
window.__xss=null; window.__hits=[];
['alert','prompt','confirm'].forEach(function(fn){{
  var o=window[fn];
  window[fn]=function(x){{ window.__xss=fn+':'+String(x); window.__hits.push(window.__xss); return o?o.call(window,x):undefined; }};
}});
// taint innerHTML setter to log writes containing sentinel
try{{
 var d=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');
 Object.defineProperty(Element.prototype,'innerHTML',{{set:function(v){{ if((''+v).indexOf('{SENT}')>=0) window.__hits.push('innerHTML<-'+(''+v).slice(0,80)); return d.set.call(this,v);}}, get:d.get, configurable:true}});
}}catch(e){{}}
window.__sent='{SENT}';
"""

def drv():
    o=Options()
    for a in ["--headless=new","--no-sandbox","--disable-gpu","--disable-dev-shm-usage","--window-size=1280,1024"]:
        o.add_argument(a)
    o.binary_location="/usr/bin/google-chrome"
    return webdriver.Chrome(options=o)

def run(url):
    d=drv()
    try:
        # warm origin (so addScriptToEvaluateOnNewDocument applies before nav)
        from urllib.parse import urlparse
        origin=urlparse(url).scheme+"://"+urlparse(url).netloc
        d.get(origin+"/")
        d.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument",{"source":HOOK})
        d.get(url)
        time.sleep(5)
        # dismiss any native dialog that may block (alert hooked, but just in case)
        try:
            a=d.switch_to.alert; txt=a.text; a.accept(); print("NATIVE_DIALOG:",txt)
        except Exception: pass
        xss=d.execute_script("return window.__xss;")
        hits=d.execute_script("return window.__hits;")
        dom=d.execute_script("return document.documentElement.outerHTML;")
        i=dom.find(SENT)
        ctx=repr(dom[max(0,i-70):i+90]) if i>=0 else "NOT_IN_DOM"
        # raw tag? sentinel followed/preceded by < indicates tag injection rendered
        raw_tag = (("<"+SENT in dom) or (SENT+">" in dom) or ("<img" in dom.lower() and SENT in dom))
        print(json.dumps({"url":url,"EXECUTED":xss,"hits":hits,"sentinel_in_dom":i>=0,"raw_tag":raw_tag,"ctx":ctx}, ensure_ascii=False))
        return xss
    finally:
        d.quit()

if __name__=="__main__":
    if len(sys.argv)<2:
        print("usage: xss_confirm.py <url>"); sys.exit(1)
    run(sys.argv[1])
