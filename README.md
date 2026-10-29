# PinGraph

[English README](README.md) | [Русский README](README_RU.md)

Minimalist local client and neural graph reconstructor for Pinterest recommendation feeds. Extracts algorithmic seed nodes, packs them into secure cryptographic tokens (`vp1_`), and renders a clean, ad-free masonry grid with infinite scrolling and zoom lightbox capabilities.

## Features

* **Ad-Free Graph Parsing:** Automatically filters out promotional ads, sponsored carousels, and commercial injection blocks using structural ID range validation.
* **Encrypted Vibe Tokens (`vp1_`):** Securely pack and share recommendation states without exposing session tokens or private keys (utilizing SHA256-CTR and HMAC-SHA256).
* **Frozen Masonry Layout:** 4-column balanced grid that prevents element shifting during infinite wave pagination.
* **Local Lightbox with Zoom:** Built-in modal viewer with mouse wheel zoom, pan dragging, and full-resolution image inspection.
* **Zero-Config Session Grabber:** Automatically reads local browser cookie stores to replicate personal recommendation feeds on demand.

## Installation & Usage

1. Clone the repository:
```bash
   git clone [https://github.com/ollxel/pin-graph.git](https://github.com/ollxel/pin-graph.git)
   cd pingraph
```
2. Run the script:
```Bash
    python3 main.py
```
3. Open your browser at:
`http://localhost:8080`
