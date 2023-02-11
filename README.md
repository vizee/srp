# srp

Simple Reverse Proxy

example:
```
openssl rand -out srp.key 32 # generate key file

# Host A
srp link -k @./srp.key

# Host B
srp agent -k @./srp.key -r host-a:7771 -t localhost:80

# Your shell
curl host-a:7770 # access host-b:80
```
