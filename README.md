# Domain Expiration

Simple command-line tool to check domain

## Installation
```
# Clone repository
$ git clone https://github.com/jffin/domain_expiration.git

# Install dependensies
# python -m pip install -r requirements.txt
```

## Usage
```.env
usage: domain_expiration.py [-h] -t TARGET [-o OUTPUT] [-w] [-j] [-q]

Domain Expiration

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET domain name
                        target url
  -o OUTPUT, --output OUTPUT
                        file to save result in
  -w, --write           write results to file
  -j, --json            json output
  -q, --quiet           quiet mod, only save to file
```

## Output
Domain info:
is exist, is expired, if will expire soon
expiration date, creation date, updated date, country
can be written to a file or into terminal output in text or JSON formats


## Whois Installation
Also, you need to have installed whois on your computer.<br>
In most Linux operating systems, whois is already available.<br>
If not, install it. For example:

For Apple macOS:
```
$ brew install whois
```

For Debian based:
```
$ sudo apt update && sudo apt upgrade
$ sudo apt install whois
```

For RHEL 6.x/RHEL 7.x/CentOS 6.x/CentOS 7.x:
```
$ sudo yum install jwhois
```

For RHEL 8.x/CentOS 8.x/Fedora 22 and higher:
```
$ sudo dnf install jwhois
```

For Arch/Manjaro:
```
$ sudo pacman -S whois
```
