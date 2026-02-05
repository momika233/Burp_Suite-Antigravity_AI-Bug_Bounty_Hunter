# Burp_Suite-Antigravity_AI-Bug_Bounty_Hunter


## Article:[https://x.com/momika233/status/2014354189082898652](https://x.com/momika233/status/2014354189082898652)

## Article:[https://x.com/momika233/status/2013984992481673479](https://x.com/momika233/status/2013984992481673479)

# Code Architecture
┌─────────────────────────────────────────────────────────────────┐
│                    Burp Suite Extension                         │
│                                                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │   HTTP Listener │───►│ Regex Fast-Path │───►│ Add Issue   │ │
│  │  (IHttpListener)│    │ HIGH_CONFIDENCE │    │ (quick hit) │ │
│  └─────────────────┘    └────────┬────────┘    └─────────────┘ │
│                                  │                              │
│                                  ▼                              │
│                         ┌─────────────────┐                    │
│                         │   LLM Analysis  │                    │
│                         │ (Claude Opus)   │                    │
│                         │ localhost:8045  │                    │
│                         └────────┬────────┘                    │
│                                  │                              │
│                                  ▼                              │
│                         ┌─────────────────┐                    │
│                         │  Parse JSON     │                    │
│                         │  Add AI Issues  │                    │
│                         └─────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
# Optimization log
## 2026.2.5 
### 1. De duplication mechanism: Use MD5 hash to track reported (URL+Issue Name) and avoid duplicate reports
### 2. Response volume sampling: Intelligent extraction of up to 3KB response content: first 1500 characters+keyword context+last 500 characters
### 3. Response header sampling: Extract the response headers of interest (x - *, auth, token, debug, etc.) and send them to LLM
### 4. JS endpoint extraction: 17 regular patterns to automatically extract API endpoints from JS files
### 5. IDOR automatic testing: IDOR automatic testing performs ID replacement testing on discovered endpoints (10 test values)
### 6. Regular rules for deduplication: Removed 4 duplicate detection rules from the original code
##  workflow
┌─────────────────────────────────────────────────────────────────┐
│                    HTTP Response Received                        │
└─────────────────────────────────────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                                  ▼
   ┌──────────────────┐               ┌──────────────────┐
   │ Content-Type:    │               │ Content-Type:    │
   │ html/json/xml    │               │ javascript       │
   └────────┬─────────┘               └────────┬─────────┘
            │                                   │
            ▼                                   ▼
   ┌──────────────────┐               ┌──────────────────┐
   │ 1. Regex Check   │               │ JS Endpoint      │
   │ 2. LLM Analysis  │               │ Extraction       │
   │    (with body    │               └────────┬─────────┘
   │     sample)      │                        │
   └────────┬─────────┘                        ▼
            │                         ┌──────────────────┐
            │                         │ IDOR Testing     │
            │                         │ (ID replacement) │
            │                         └────────┬─────────┘
            │                                   │
            ▼                                   ▼
   ┌──────────────────────────────────────────────────┐
   │              Deduplication Check                  │
   │         (Hash: URL + Issue Name)                  │
   └──────────────────────────────────────────────────┘
                               │
                               ▼
   ┌──────────────────────────────────────────────────┐
   │              Add to Burp Issues                   │
   └──────────────────────────────────────────────────┘

## enjoy!!!!

# I welcome your questions in the Issues section
# I welcome your questions in the Issues section
# I welcome your questions in the Issues section


(I love coffee and am very addicted to coffee:v)
<br><a href="https://www.buymeacoffee.com/momika233"><img src="https://cdn.buymeacoffee.com/buttons/default-black.png" alt="Buy Me A Coffee" height="50px"></a>



## Stargazers over time
[![Stargazers over time](https://starchart.cc/momika233/Burp_Suite-Antigravity_AI-Bug_Bounty_Hunter.svg?variant=adaptive)](https://starchart.cc/momika233/Burp_Suite-Antigravity_AI-Bug_Bounty_Hunter)
