# FireEye2TH: FireEye iSIGHT Alert Feeder for TheHive 
[FireEye](https://www.FireEye.com/) is a commercial Threat 
Intelligence provider which, according to their website:

> FireEye iSIGHT Threat Intelligence is a proactive, forward-looking means of qualifying threats poised to disrupt your business based on the intents, tools and tactics of the attacker. Our high-fidelity, comprehensive intelligence delivers visibility beyond the typical attack lifecycle, adding context and priority to global threats before, during and after an attack.
It helps mitigate risk, bolster incident response, and enhance your overall security ecosystem. Get the intel you need to predict attack and refocus your attention on what matters most to your business.

FireEye2TH is a free, open source FireEye iSIGHT alert feeder for 
TheHive. You can use it to import 
FireEye *incidents* as alerts in TheHive, where they can be previewed and 
transformed into new cases using pre-defined incident response templates or 
added into existing ones.

FireEyes2TH is written in Python 3 by LDO-CERT.

## Overview
FireEye2TH is made of several parts:

- `FireEye/api.py` : the main library to interact with the 
FireEye API and fetch *incidents*.
- `config.py.template` : a configuration template which contains all the 
necessary information to connect to the APIs of FireEye iSIGHT and TheHive. 
All information is required.
- `fe2th.py` : the main program. It gets FireEye iSIGHT *incidents* and creates alerts in TheHive with a description containing 
all relevant information, and observables if any.

## Prerequisites
You'll need Python 3, the `requests` library and [TheHive4py](https://github.com/CERT-BDF/TheHive4py), 
a Python client for TheHive.

[html2text](http://alir3z4.github.io/html2text/) library is used to convert html response in markdown.

Clone the repository then copy the `config.py.template` file as `config.py` 
and fill in the blanks: proxies if applicable, API keys, URLs, accounts 
pertaining to your FireEye iSIGHT subscription and your instance of TheHive.

**Note**: you need TheHive 2.13 or better and an account with the ability to create alerts.

Then install the Python requirements:

`$ pip3 install -r requirements.txt`

## Configuration parameters
`ignored_tags` contains a list of tag that you wants to ignore.
Some of the available tags are: `intendedEffect,affectedSystem,ttp,affectedIndustry,targetedInformation,targetGeography`

## Usage
Once your configuration file `config.py` is ready, use the main program to 
fetch or find FireEye (FE) *incidents*:

```
./fe2th.py -h
usage: fe2th.py [-h] [-d] {inc,find} ...

Get FE iSIGHT alerts and create alerts in TheHive

positional arguments:
  {inc,find}   subcommand help
    inc        fetch incidents by ID
    find       find incidents in time

optional arguments:
  -h, --help   show this help message and exit
  -d, --debug  generate a log file and and active debug logging
```

The program comes with 2 commands:
- `inc` to fetch *incidents* by their IDs
- `find` to fetch *incidents* published during the last M minutes. 

If you need debbuging information, add the `d`switch and the program will 
create a file called `fe2th.log`. It will be created in the same folder as the 
main program.

### Retrieve incidents specified by their ID

```
./fe2th.py inc -h
usage: fe2th.py inc [-h] [-i ID [ID ...]] [-I ID [ID ...]]

optional arguments:
  -h, --help            show this help message and exit
  -i ID [ID ...], --incidents ID [ID ...]
                        Get FE incidents by ID
```

- `./fe2th.py inc -i 1234567 2345678` : fetch incidents with IDs 1234567 and 2345678.

### Retrieve incidents published during the last `M` minutes

```
./fe2th.py find -h
usage: fe2th.py find [-h] -l M [-m]

optional arguments:
  -h, --help      show this help message and exit
  -l M, --last M  Get all incidents published during the last [M] minutes
  -m, --monitor   active monitoring
```

- `./fe2th.py find -l 20` retrieves incidents published during the last 20 minutes.
- `m` is a switch that creates a `fe2th.status` file. This is useful if you want to add the program as a cron job and monitor it. 

### Use Cases

- Fetch incident #123456

```
$ ./fe2th.py inc -i 123456
```

- Add a cron job and check for new published incidents every 10 mins:

```
*/10    *   *   *   * /path/to/fe2th.py find -l 15
```

- Enable logging:

```
*/10    *   *   *   * /path/to/fe2th.py -d find -l 15
```

This will create a `fe2th.log` file in the folder of the main program.

### Monitoring 

- Monitor the feeder

```
*/10    *   *   *   * /path/to/fe2th.py find -l 15 -m
```

The monitoring switch makes the program "touch" a file named
`fe2th.status` once it has successfully finished. To monitor it, just check
the modification date of this file and compare it to the frequency used
in your crontab entry.
