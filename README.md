# shodanXtract

is a command-line tool written in Go that fetches IP addresses from Shodan based on various inputs such as IP ranges, domains, and custom query strings. The tool allows users to pipe input from text files and retrieve relevant IP addresses from Shodan's search results.

## Features

- Fetch IP addresses from IP ranges
- Fetch IP addresses associated with domains
- Fetch IP addresses based on custom query strings

1. Ensure you have Go installed on your system. You can download and install Go from [the official website](https://go.dev/dl/).

2. Clone this repository:

`git clone https://github.com/Vulnpire/shodanXtract`

3. Build the executable:

`go build -o sXtract main.go`

## Usage

The tool supports three main flags to specify the type of input:

    -ir : Fetch IP addresses from IP ranges.
    -ip : Fetch IP addresses associated with domains.
    -q : Fetch IP addresses based on custom query strings.

Fetching IPs from IP ranges

Provide a text file with IP ranges, one per line, and use the -ir flag:

`cat ipranges.txt | sXtract -ir`

Fetching IPs from domains

Provide a text file with domain names, one per line, and use the -ip flag:

`cat domains.txt | sXtract -ip`

Fetching IPs from a CVE query strings

Provide a text file with custom query strings, one per line, and use the -q flag:

`cat queries.txt | sXtract -q`

## Port scan using Shodan

```
cat << EOF > wildcards.txt
> spotify.com
> EOF
```

`cat wildcards.txt | sXtract -ip | anew ips.txt && for i in $(cat ips.txt);do shodan host $i;done`

![image](https://github.com/user-attachments/assets/5e574a3f-17fd-4dc6-bbb0-8edbc71c1199)
