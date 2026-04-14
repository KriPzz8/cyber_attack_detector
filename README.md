# Web Interface

This folder contains a fully functional frontend for the cyber attack detector.

## Features

- paste network traffic data
- choose one of three detection modes
- run KMP, Boyer-Moore, or Aho-Corasick
- view detected attack signatures
- compare all algorithms on the same input

## Open Locally

You can open `index.html` directly in a browser, or serve the folder locally:

```powershell
cd C:\Users\Khantil\Downloads\cyber_attack_detector\web
python -m http.server 8000
```

Then visit `http://localhost:8000`.
