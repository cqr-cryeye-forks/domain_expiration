# Domain Expiration

Simple command-line tool check domain

## Installation
```
git clone 
```


## Usage
```.env
usage: domain_expiration.py [-h] -t TARGET [-o OUTPUT] [-w] [-j] [-q]

Domain Expiration

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target url
  -o OUTPUT, --output OUTPUT
                        file to save result in
  -w, --write           write results to file
  -j, --json            json output
  -q, --quiet           quiet mod, only save to file
```

## Output
Domain info:
is expired, if will expire soon
expiration date, creation date, updated date, country
can be written to a file or into terminal output in text or JSON formats
