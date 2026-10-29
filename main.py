import http.server
import urllib.request
import urllib.parse
import http.cookiejar
import json
import re
import ssl
import struct
import base64
import hashlib
import hmac
import os
import glob
import sqlite3
import shutil
import tempfile
import secrets

PORT = 8080
CONFIG_FILE = os.path.expanduser("~/.pingraph_keys.json")

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookie_jar),
    urllib.request.HTTPSHandler(context=ssl_ctx)
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

SESSION_STATE = {
    "private_key": "",
    "public_key": "",
    "cookie": "",
    "bookmarks": {},
    "next_seeds": {},
    "seen_pins": set()
}

def init_crypto_keys():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                SESSION_STATE["private_key"] = data["private_key"]
                SESSION_STATE["public_key"] = data["public_key"]
                SESSION_STATE["cookie"] = data.get("cookie", "")
                return
        except Exception:
            pass

    priv_raw = secrets.token_bytes(16)
    SESSION_STATE["private_key"] = "sk_" + priv_raw.hex()
    SESSION_STATE["public_key"] = "pk_" + hashlib.sha256(priv_raw).hexdigest()[:24]
    save_crypto_keys()

def save_crypto_keys():
    with open(CONFIG_FILE, "w") as f:
        json.dump({
            "private_key": SESSION_STATE["private_key"],
            "public_key": SESSION_STATE["public_key"],
            "cookie": SESSION_STATE["cookie"]
        }, f, indent=2)

def encode_vibe_token(pin_ids, pub_key_str=None):
    pub = (pub_key_str or SESSION_STATE["public_key"]).strip().encode("utf-8")
    nonce = secrets.token_bytes(4)
    raw_ids = b"".join(struct.pack(">Q", int(x)) for x in pin_ids[:6])

    keystream = (
        hashlib.sha256(pub + nonce + b"\x00").digest() +
        hashlib.sha256(pub + nonce + b"\x01").digest()
    )[:len(raw_ids)]

    cipher = bytes(a ^ b for a, b in zip(raw_ids, keystream))
    mac = hmac.new(pub, nonce + cipher, hashlib.sha256).digest()[:4]

    payload = nonce + mac + cipher
    b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"vp1_{b64}"

def decode_vibe_token(token_str, pub_key_str=None):
    token_str = token_str.strip()
    if token_str.startswith("vp1_"):
        b64 = token_str[4:].replace("-", "+").replace("_", "/")
        padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
        payload = base64.b64decode(padded)
        nonce, mac, cipher = payload[:4], payload[4:8], payload[8:]

        pub = (pub_key_str or SESSION_STATE["public_key"]).strip().encode("utf-8")
        expected_mac = hmac.new(pub, nonce + cipher, hashlib.sha256).digest()[:4]
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Invalid Public Key for this token.")

        keystream = (
            hashlib.sha256(pub + nonce + b"\x00").digest() +
            hashlib.sha256(pub + nonce + b"\x01").digest()
        )[:len(cipher)]
        raw_ids = bytes(a ^ b for a, b in zip(cipher, keystream))
    else:
        b64 = token_str.replace("-", "+").replace("_", "/")
        padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
        raw_ids = base64.b64decode(padded)

    ids = []
    for i in range(len(raw_ids) // 8):
        val = struct.unpack(">Q", raw_ids[i*8:(i+1)*8])[0]
        if val > 0:
            ids.append(str(val))
    return ids

def auto_extract_local_browser_cookies():
    search_patterns = [
        os.path.expanduser("~/Library/Application Support/zen/Profiles/*/cookies.sqlite"),
        os.path.expanduser("~/Library/Application Support/Zen/Profiles/*/cookies.sqlite"),
        os.path.expanduser("~/Library/Application Support/Zen Browser/Profiles/*/cookies.sqlite"),
        os.path.expanduser("~/Library/Application Support/Firefox/Profiles/*/cookies.sqlite"),
        os.path.expanduser("~/Library/Application Support/*/Profiles/*/cookies.sqlite"),
        os.path.expanduser("~/.zen/*/cookies.sqlite"),
        os.path.expanduser("~/.mozilla/firefox/*/cookies.sqlite"),
    ]

    found_dbs = []
    for pat in search_patterns:
        for p in glob.glob(pat, recursive=True):
            if p.endswith("cookies.sqlite") and p not in found_dbs:
                found_dbs.append(p)

    found_dbs.sort(key=lambda x: os.path.getmtime(x), reverse=True)

    for db_path in found_dbs:
        tmp_dir = tempfile.mkdtemp()
        try:
            tmp_db = os.path.join(tmp_dir, "cookies.sqlite")
            shutil.copy2(db_path, tmp_db)
            for ext in ("-wal", "-shm"):
                if os.path.exists(db_path + ext):
                    shutil.copy2(db_path + ext, tmp_db + ext)

            conn = sqlite3.connect(tmp_db)
            cur = conn.cursor()
            cur.execute("SELECT name, value FROM moz_cookies WHERE host LIKE '%pinterest.%'")
            rows = cur.fetchall()
            conn.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)

            cookie_dict = {k: v for k, v in rows}
            if "_pinterest_sess" in cookie_dict:
                return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return ""

def is_organic_pin_id(pin_id_str):
    if not pin_id_str.isdigit():
        return False
    if len(pin_id_str) < 15 or len(pin_id_str) > 18:
        return False
    if int(pin_id_str) > 1_800_000_000_000_000_000:
        return False
    return True

def init_pinterest_session():
    try:
        req = urllib.request.Request("https://www.pinterest.com/", headers=HEADERS)
        opener.open(req, timeout=8)
    except Exception:
        pass

def parse_structured_pins(obj, collected):
    if isinstance(obj, dict):
        if (
            obj.get("is_promoted")
            or obj.get("is_Unsafe")
            or obj.get("promoter")
            or obj.get("ad_match_reason")
            or obj.get("promoted_is_lead_ad")
            or obj.get("is_eligible_for_related_products") and obj.get("shopping_flags")
        ):
            return

        pin_id = str(obj.get("id", ""))
        images = obj.get("images")

        if is_organic_pin_id(pin_id) and isinstance(images, dict):
            grid_url = ""
            hd_url = ""
            for size in ("736x", "564x", "474x", "orig", "236x"):
                if size in images and isinstance(images[size], dict) and "url" in images[size]:
                    grid_url = images[size]["url"]
                    break
            for size in ("orig", "originals", "736x", "564x"):
                if size in images and isinstance(images[size], dict) and "url" in images[size]:
                    hd_url = images[size]["url"]
                    break

            if grid_url and pin_id not in collected:
                collected[pin_id] = {
                    "pin_id": pin_id,
                    "img": grid_url,
                    "hd_img": hd_url or grid_url,
                }

        for k, v in obj.items():
            if k in (
                "board", "signup_banners", "trending_queries", "shopping_ads",
                "promoted_pins", "insertion", "ad_data", "carousel_data", "rich_summary"
            ):
                continue
            parse_structured_pins(v, collected)
    elif isinstance(obj, list):
        for item in obj:
            parse_structured_pins(item, collected)

def extract_bookmark(obj):
    if isinstance(obj, dict):
        if "bookmark" in obj and isinstance(obj["bookmark"], str) and obj["bookmark"] != "-end-":
            return obj["bookmark"]
        for v in obj.values():
            res = extract_bookmark(v)
            if res:
                return res
    elif isinstance(obj, list):
        for item in obj:
            res = extract_bookmark(item)
            if res:
                return res
    return None

def call_pinterest_resource(resource_name, source_url, options_dict, custom_cookie=""):
    csrf = next((c.value for c in cookie_jar if c.name == 'csrftoken'), '')
    if custom_cookie:
        m = re.search(r'csrftoken=([^;]+)', custom_cookie)
        if m:
            csrf = m.group(1)

    data_str = json.dumps({"options": options_dict, "context": {}})
    url = f"https://www.pinterest.com/resource/{resource_name}/get/?source_url={urllib.parse.quote(source_url)}&data={urllib.parse.quote(data_str)}"

    req_headers = dict(HEADERS)
    req_headers.update({
        "Accept": "application/json, text/javascript, */*, q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "X-Pinterest-AppState": "active",
        "X-Pinterest-Source-Url": source_url,
        "X-Pinterest-PWS-Handler": "www/pin/[id].js",
        "X-CSRFToken": csrf,
        "Referer": f"https://www.pinterest.com{source_url}"
    })
    if custom_cookie:
        req_headers["Cookie"] = custom_cookie

    req = urllib.request.Request(url, headers=req_headers)
    with opener.open(req, timeout=10) as resp:
        return json.loads(resp.read().decode('utf-8', errors='ignore'))

def auto_fetch_my_homefeed_seeds():
    cookie = SESSION_STATE["cookie"]
    collected = {}

    try:
        req_headers = dict(HEADERS)
        if cookie:
            req_headers["Cookie"] = cookie
        req = urllib.request.Request("https://www.pinterest.com/", headers=req_headers)
        with opener.open(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            json_blocks = re.findall(r'<script[^>]*type="application/json"[^>]*>(.*?)</script>', html, re.DOTALL)
            for block in json_blocks:
                try:
                    parse_structured_pins(json.loads(block), collected)
                except Exception:
                    pass
    except Exception:
        pass

    if len(collected) < 6 and cookie:
        try:
            feed_json = call_pinterest_resource("UserHomefeedResource", "/", {"page_size": 25}, cookie)
            parse_structured_pins(feed_json, collected)
        except Exception:
            pass

    all_ids = [pid for pid in collected.keys() if is_organic_pin_id(pid)]
    if len(all_ids) >= 6:
        step = max(1, len(all_ids) // 6)
        return [all_ids[i * step] for i in range(6)]
    return all_ids[:6]

def fetch_infinite_branch(root_seed_id, page=1):
    if not is_organic_pin_id(str(root_seed_id)):
        return []

    collected = {}
    active_cookie = SESSION_STATE["cookie"]

    target_pin_id = str(root_seed_id)
    if page > 1:
        children = SESSION_STATE["next_seeds"].get(root_seed_id, [])
        if children:
            target_pin_id = children[(page - 2) % len(children)]

    pin_title = ""
    try:
        req_headers = dict(HEADERS)
        if active_cookie:
            req_headers["Cookie"] = active_cookie
        req = urllib.request.Request(f"https://www.pinterest.com/pin/{target_pin_id}/", headers=req_headers)
        with opener.open(req, timeout=10) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            json_blocks = re.findall(r'<script[^>]*type="application/json"[^>]*>(.*?)</script>', html, re.DOTALL)
            for block in json_blocks:
                try:
                    parse_structured_pins(json.loads(block), collected)
                except Exception:
                    pass
            title_m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_m:
                pin_title = re.sub(r'\s*\|\s*Pinterest.*$', '', title_m.group(1)).strip()
    except Exception:
        pass

    bookmark = SESSION_STATE["bookmarks"].get(root_seed_id)

    try:
        opts = {"pin": str(target_pin_id), "page_size": 15}
        if bookmark and page > 1:
            opts["bookmarks"] = [bookmark]
        rel_json = call_pinterest_resource("RelatedPinFeedResource", f"/pin/{target_pin_id}/", opts, active_cookie)
        parse_structured_pins(rel_json, collected)
        new_bm = extract_bookmark(rel_json)
        if new_bm:
            SESSION_STATE["bookmarks"][root_seed_id] = new_bm
    except Exception:
        pass

    if len(collected) < 6 and pin_title and pin_title.lower() != "pinterest":
        try:
            s_opts = {"query": pin_title, "scope": "pins", "page_size": 15}
            if bookmark and page > 1:
                s_opts["bookmarks"] = [bookmark]
            s_json = call_pinterest_resource(
                "BaseSearchResource",
                f"/search/pins/?q={urllib.parse.quote(pin_title)}",
                s_opts,
                active_cookie
            )
            parse_structured_pins(s_json, collected)
            new_bm = extract_bookmark(s_json)
            if new_bm:
                SESSION_STATE["bookmarks"][root_seed_id] = new_bm
        except Exception:
            pass

    child_ids = [pid for pid in collected.keys() if pid != str(root_seed_id) and is_organic_pin_id(pid)]
    if child_ids:
        existing = SESSION_STATE["next_seeds"].setdefault(root_seed_id, [])
        for cid in child_ids:
            if cid not in existing:
                existing.append(cid)

    fresh_pins = []
    if page == 1 and str(root_seed_id) in collected:
        seed_obj = collected.pop(str(root_seed_id))
        if seed_obj["pin_id"] not in SESSION_STATE["seen_pins"]:
            SESSION_STATE["seen_pins"].add(seed_obj["pin_id"])
            seed_obj["is_seed"] = True
            fresh_pins.append(seed_obj)

    for pid, item in collected.items():
        if pid not in SESSION_STATE["seen_pins"]:
            SESSION_STATE["seen_pins"].add(pid)
            item["is_seed"] = False
            fresh_pins.append(item)

    return fresh_pins[:10]


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PinGraph</title>
  <style>
    * { box-sizing: border-box; }
    body { background: #0b0b0b; color: #e5e5e5; font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 24px; }
    .top-bar { max-width: 980px; margin: 0 auto 28px; display: flex; gap: 12px; flex-direction: column; background: #141414; padding: 20px; border-radius: 16px; border: 1px solid #262626; }
    .row { display: flex; width: 100%; gap: 10px; align-items: center; }
    .keys-bar { display: flex; gap: 10px; font-family: monospace; font-size: 12px; background: #0d0d0d; padding: 10px 14px; border-radius: 10px; border: 1px solid #222; align-items: center; justify-content: space-between; flex-wrap: wrap; }
    .key-pill { display: flex; align-items: center; gap: 8px; }
    .key-val { color: #10b981; background: #181818; padding: 4px 8px; border-radius: 6px; user-select: all; }
    .priv-val { color: #f59e0b; filter: blur(4px); transition: 0.2s; cursor: pointer; }
    .priv-val:hover { filter: none; }
    input { flex: 1; padding: 12px 16px; border-radius: 10px; border: 1px solid #2a2a2a; background: #0d0d0d; color: #fff; font-family: monospace; font-size: 13px; outline: none; }
    input:focus { border-color: #e60023; }
    button { padding: 12px 18px; border-radius: 10px; border: none; background: #e60023; color: #fff; font-weight: 700; cursor: pointer; white-space: nowrap; transition: 0.15s; }
    button:hover { background: #ff1a3c; }
    .btn-auto { background: #10b981; color: #052e16; }
    .btn-auto:hover { background: #34d399; }
    .status { font-size: 13px; color: #aaa; font-family: monospace; display: flex; justify-content: space-between; align-items: center; }

    .masonry-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; max-width: 1350px; margin: 0 auto; align-items: start; }
    @media (max-width: 1000px) { .masonry-grid { grid-template-columns: repeat(3, 1fr); } }
    @media (max-width: 650px) { .masonry-grid { grid-template-columns: repeat(2, 1fr); } }
    .masonry-col { display: flex; flex-direction: column; gap: 16px; }

    .pin { border-radius: 14px; overflow: hidden; background: #161616; border: 1px solid #222; transition: transform 0.15s ease; }
    .pin.seed-pin { border: 2px solid #e60023; }
    .pin:hover { transform: translateY(-3px); border-color: #3a3a3a; }
    .pin-img-wrap { cursor: zoom-in; overflow: hidden; }
    .pin img { width: 100%; display: block; min-height: 120px; background: #1f1f1f; }
    .pin-meta { padding: 9px 12px; font-size: 11px; color: #888; display: flex; justify-content: space-between; align-items: center; background: #131313; }
    .pin-link { color: #ccc; text-decoration: none; font-weight: 600; font-family: monospace; padding: 3px 7px; border-radius: 6px; background: #222; transition: 0.15s; }
    .pin-link:hover { background: #e60023; color: #fff; }
    .badge { padding: 2px 6px; border-radius: 6px; background: #262626; font-family: monospace; }
    .seed-pin .badge { background: #e60023; color: #fff; }
    .loader { text-align: center; padding: 40px; font-family: monospace; color: #777; font-size: 14px; }

    .lightbox { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.92); backdrop-filter: blur(8px); z-index: 99999; display: none; flex-direction: column; align-items: center; justify-content: center; user-select: none; overflow: hidden; }
    .lightbox.open { display: flex; }
    .lb-toolbar { position: fixed; top: 20px; right: 24px; display: flex; gap: 10px; z-index: 100001; align-items: center; }
    .lb-btn { background: #222; color: #fff; border: 1px solid #444; padding: 8px 14px; border-radius: 10px; font-family: monospace; font-size: 13px; cursor: pointer; text-decoration: none; }
    .lb-btn:hover { background: #e60023; border-color: #e60023; }
    .lb-stage { width: 100vw; height: 100vh; display: flex; align-items: center; justify-content: center; cursor: grab; }
    .lb-stage:active { cursor: grabbing; }
    .lb-stage img { max-width: 88vw; max-height: 88vh; border-radius: 10px; box-shadow: 0 12px 50px rgba(0,0,0,0.8); transform-origin: center center; transition: transform 0.06s ease-out; pointer-events: none; }
    .lb-hint { position: fixed; bottom: 18px; color: #888; font-family: monospace; font-size: 12px; background: rgba(20,20,20,0.85); padding: 6px 14px; border-radius: 20px; pointer-events: none; }
  </style>
</head>
<body>
  <div class="top-bar">
    <div class="keys-bar">
      <div class="key-pill">
        <span>Public Key:</span>
        <span class="key-val" id="myPubKey">__PUB_KEY__</span>
      </div>
      <div class="key-pill">
        <span>Private Key:</span>
        <span class="key-val priv-val" id="myPrivKey">__PRIV_KEY__</span>
      </div>
      <div class="key-pill">
        <span id="cookieBadge" style="color:__COOKIE_COLOR__;">__COOKIE_STATUS__</span>
      </div>
    </div>

    <div class="row">
      <input id="hashInput" value="__DEFAULT_HASH__" placeholder="Enter Vibe Hash (vp1_...)..." />
      <input id="authorPubKey" value="__PUB_KEY__" style="max-width: 240px;" placeholder="Author Public Key (pk_...)" />
      <button onclick="resetAndStart()">Load Hash</button>
      <button class="btn-auto" onclick="autoGrabFromBrowser()">Grab Homefeed</button>
    </div>

    <div class="status">
      <span id="status">Ready. Ads filtered. Click image for zoom, click ID for Pinterest.</span>
      <span id="counter">Pins: 0 | Wave: 0</span>
    </div>
  </div>

  <div class="masonry-grid" id="grid">
    <div class="masonry-col" id="col-0"></div>
    <div class="masonry-col" id="col-1"></div>
    <div class="masonry-col" id="col-2"></div>
    <div class="masonry-col" id="col-3"></div>
  </div>
  <div class="loader" id="scrollLoader">Scroll down for infinite stream...</div>

  <div class="lightbox" id="lightbox">
    <div class="lb-toolbar">
      <button class="lb-btn" onclick="zoomStep(0.4)">Zoom In</button>
      <button class="lb-btn" onclick="zoomStep(-0.4)">Zoom Out</button>
      <button class="lb-btn" onclick="resetZoom()">100%</button>
      <a class="lb-btn" id="lbPinLink" href="#" target="_blank">Open in Pinterest</a>
      <button class="lb-btn" onclick="closeLightbox()">Close (Esc)</button>
    </div>
    <div class="lb-stage" id="lbStage">
      <img id="lbImage" src="" referrerpolicy="no-referrer" />
    </div>
    <div class="lb-hint">Wheel: zoom • Drag: pan • Double click: reset • Click background or Esc: close</div>
  </div>

  <script>
    let currentPage = 0;
    let isLoading = false;
    let activePinIds = [];
    let totalPinsCount = 0;

    let scale = 1, panX = 0, panY = 0, isDragging = false, startX = 0, startY = 0;
    const lb = document.getElementById('lightbox');
    const lbImg = document.getElementById('lbImage');
    const lbStage = document.getElementById('lbStage');

    function updateTransform() {
      lbImg.style.transform = `translate(${panX}px, ${panY}px) scale(${scale})`;
    }

    function openLightbox(hdUrl, fallbackUrl, pinId) {
      scale = 1; panX = 0; panY = 0;
      updateTransform();
      lbImg.onerror = () => { if (lbImg.src !== fallbackUrl) lbImg.src = fallbackUrl; };
      lbImg.src = hdUrl;
      document.getElementById('lbPinLink').href = `https://www.pinterest.com/pin/${pinId}/`;
      lb.classList.add('open');
    }

    function closeLightbox() {
      lb.classList.remove('open');
      lbImg.src = '';
    }

    function zoomStep(delta) {
      scale = Math.min(Math.max(0.5, scale + delta), 6);
      updateTransform();
    }

    function resetZoom() {
      scale = 1; panX = 0; panY = 0;
      updateTransform();
    }

    lbStage.addEventListener('wheel', (e) => {
      e.preventDefault();
      const delta = e.deltaY < 0 ? 0.25 : -0.25;
      scale = Math.min(Math.max(0.5, scale + delta), 6);
      updateTransform();
    }, { passive: false });

    lbStage.addEventListener('mousedown', (e) => {
      if (e.target !== lbStage) return;
      isDragging = true;
      startX = e.clientX - panX;
      startY = e.clientY - panY;
    });

    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      panX = e.clientX - startX;
      panY = e.clientY - startY;
      updateTransform();
    });

    window.addEventListener('mouseup', (e) => {
      if (isDragging && Math.abs(e.clientX - (startX + panX)) < 4 && Math.abs(e.clientY - (startY + panY)) < 4 && scale === 1) {
        closeLightbox();
      }
      isDragging = false;
    });

    lbStage.addEventListener('dblclick', () => {
      scale = scale === 1 ? 2.5 : 1;
      panX = 0; panY = 0;
      updateTransform();
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeLightbox();
    });

    function clearColumns() {
      for (let i = 0; i < 4; i++) {
        document.getElementById(`col-${i}`).innerHTML = '';
      }
    }

    function appendPinToShortestCol(item) {
      let minCol = 0;
      let minVal = document.getElementById('col-0').offsetHeight;
      for (let i = 1; i < 4; i++) {
        const h = document.getElementById(`col-${i}`).offsetHeight;
        if (h < minVal) {
          minVal = h;
          minCol = i;
        }
      }

      const div = document.createElement('div');
      div.className = 'pin' + (item.is_seed ? ' seed-pin' : '');
      const hd = item.hd_img || item.img;
      div.innerHTML = `
        <div class="pin-img-wrap">
          <img src="${item.img}" referrerpolicy="no-referrer" loading="lazy" />
        </div>
        <div class="pin-meta">
          <span class="badge">${item.is_seed ? 'SEED #' + item.pin_id.slice(-5) : 'Node #' + item.sourceSeed.slice(-5)}</span>
          <a class="pin-link" href="https://www.pinterest.com/pin/${item.pin_id}/" target="_blank" title="Open in Pinterest">#${item.pin_id.slice(-5)}</a>
        </div>`;

      div.querySelector('.pin-img-wrap').addEventListener('click', () => {
        openLightbox(hd, item.img, item.pin_id);
      });

      document.getElementById(`col-${minCol}`).appendChild(div);
    }

    async function autoGrabFromBrowser() {
      const status = document.getElementById('status');
      status.textContent = "Reading local session and fetching homefeed...";
      const res = await fetch('/api/auto_grab');
      const data = await res.json();
      if (data.hash) {
        document.getElementById('hashInput').value = data.hash;
        document.getElementById('authorPubKey').value = data.pub_key;
        document.getElementById('cookieBadge').textContent = data.has_cookie ? "Session Active" : "Guest Mode";
        document.getElementById('cookieBadge').style.color = data.has_cookie ? "#10b981" : "#f59e0b";
        status.textContent = `Fetched ${data.count} organic pins. Building graph...`;
        resetAndStart();
      } else {
        status.textContent = "Error: " + (data.error || "Failed to fetch homefeed");
      }
    }

    async function resetAndStart() {
      const hash = document.getElementById('hashInput').value.trim();
      const pubKey = document.getElementById('authorPubKey').value.trim();
      const status = document.getElementById('status');

      const res = await fetch(`/api/decode?hash=${encodeURIComponent(hash)}&pub_key=${encodeURIComponent(pubKey)}`);
      const data = await res.json();
      if (data.error) {
        status.textContent = "Decode error: " + data.error;
        return;
      }

      activePinIds = data.pin_ids;
      status.textContent = `Graph nodes: ${activePinIds.join(', ')}. Loading...`;
      currentPage = 0;
      totalPinsCount = 0;
      clearColumns();
      await loadNextPage();
    }

    async function loadNextPage() {
      if (isLoading || activePinIds.length === 0) return;
      isLoading = true;
      currentPage++;

      const status = document.getElementById('status');
      const loader = document.getElementById('scrollLoader');
      status.textContent = `Loading wave #${currentPage}...`;

      const clusters = await Promise.all(activePinIds.map(async (pinId) => {
        try {
          const res = await fetch(`/api/cluster?pin_id=${pinId}&page=${currentPage}`);
          const data = await res.json();
          return (data.pins || []).map(p => ({ ...p, sourceSeed: pinId }));
        } catch (e) {
          return [];
        }
      }));

      const mixedWave = [];
      const maxLen = Math.max(...clusters.map(c => c.length), 0);
      for (let i = 0; i < maxLen; i++) {
        for (let c = 0; c < clusters.length; c++) {
          if (clusters[c][i]) mixedWave.push(clusters[c][i]);
        }
      }

      mixedWave.forEach(item => {
        totalPinsCount++;
        appendPinToShortestCol(item);
      });

      document.getElementById('counter').textContent = `Pins: ${totalPinsCount} | Wave: ${currentPage}`;
      status.textContent = `Wave #${currentPage} loaded (+${mixedWave.length} pins).`;
      loader.textContent = `Scroll down for wave #${currentPage + 1}...`;
      isLoading = false;
    }

    const observer = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting && !isLoading && activePinIds.length > 0) {
        loadNextPage();
      }
    }, { rootMargin: '600px' });

    observer.observe(document.getElementById('scrollLoader'));
  </script>
</body>
</html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            has_c = bool(SESSION_STATE["cookie"])
            page = (HTML_PAGE
                .replace("__PUB_KEY__", SESSION_STATE["public_key"])
                .replace("__PRIV_KEY__", SESSION_STATE["private_key"])
                .replace("__COOKIE_STATUS__", "Session Active" if has_c else "Guest Mode")
                .replace("__COOKIE_COLOR__", "#10b981" if has_c else "#f59e0b")
            )
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(page.encode('utf-8'))
            return

        if self.path.startswith('/api/decode'):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            h = query.get('hash', [''])[0]
            pk = query.get('pub_key', [''])[0]
            SESSION_STATE["bookmarks"].clear()
            SESSION_STATE["next_seeds"].clear()
            SESSION_STATE["seen_pins"].clear()
            try:
                ids = decode_vibe_token(h, pk)
                clean_ids = [x for x in ids if is_organic_pin_id(x)]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"pin_ids": clean_ids}).encode('utf-8'))
            except Exception as e:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        if self.path.startswith('/api/auto_grab'):
            cookie = auto_extract_local_browser_cookies()
            if cookie:
                SESSION_STATE["cookie"] = cookie
                save_crypto_keys()
            seeds = auto_fetch_my_homefeed_seeds()
            if seeds:
                new_token = encode_vibe_token(seeds, SESSION_STATE["public_key"])
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "hash": new_token,
                    "pub_key": SESSION_STATE["public_key"],
                    "count": len(seeds),
                    "has_cookie": bool(SESSION_STATE["cookie"])
                }).encode('utf-8'))
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "Failed to extract homefeed seeds."
                }).encode('utf-8'))
            return

        if self.path.startswith('/api/cluster'):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            pin_id = query.get('pin_id', [''])[0]
            page = int(query.get('page', ['1'])[0])
            pins = fetch_infinite_branch(pin_id, page)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"pins": pins}).encode('utf-8'))

if __name__ == '__main__':
    init_crypto_keys()
    extracted = auto_extract_local_browser_cookies()
    if extracted:
        SESSION_STATE["cookie"] = extracted
        save_crypto_keys()

    default_seeds = []
    default_token = ""
    HTML_PAGE = HTML_PAGE.replace("__DEFAULT_HASH__", default_token)

    init_pinterest_session()
    print(f"Public Key: {SESSION_STATE['public_key']}")
    print(f"Vibe Hash: {default_token}")
    print(f"Server started at http://localhost:{PORT}")
    http.server.HTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
