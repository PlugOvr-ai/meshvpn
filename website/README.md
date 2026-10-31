# meshvpn website

Static site, no framework: page contents in `pages/`, shared header/footer in `build.py`, styles and script in `assets/`.

```sh
python3 build.py          # -> public/ (also checks that every local link resolves)
python3 -m http.server -d public 8000
```

Deploy `public/` to any static host (S3/CloudFront, GitHub Pages, nginx). Set `SITE` in `build.py` to the final
address for the canonical links.
