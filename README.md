# certwarden-client
## Lightweight and simple [Cert Warden](https://www.certwarden.com/) client

### 1. Why
I needed a simplistic client for Cert Warden certificate management service, that could be installed on the host machine to manage certificates for non-Dockerized services, which would not require a separate port and certificate for callbacks from the server (like the official client does), thus this project was born.

### 2. How it works
Very simple, really. All you need is a configuration file with the list of certificates that need to be pulled (full config example can be found [here](test/configs/allOptionsConfig.yaml)), and the program will poll the server with specified intervals, update the files on disk if needed, and optionally, run the specified command (for example, to notify the application using the certificates, that a reload is needed).

### 3. Installation
Currently, the application is provided as a Debian package or a pre-built binary, both of which can be found on the Releases page. One can also build the binary from source by running `make`
