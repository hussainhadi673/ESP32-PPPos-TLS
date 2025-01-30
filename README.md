# ESP32-PPPos-TLS
This repository implements the ESP32 pppos protocol to connect with any linux/windows machine. Also you can run server on windows to connect with ESP32 via TLS

## Setup
1. connect the esp32 pin 10,11 or whatever you prefer with FTDI converter and plug it into your linux machine.
2. install the expressif board v3.02 in your arduino IDE
3. compile the esp32 arduino IDE code and download it to the esp32.
4. Now ESP32 is waiting for the PPP connection from server. Please enter the command:
```
  sudo pppd /dev/ttyUSB0 115200 debug updetach unit 1
```

5. now the PPP connection is established.
6. run the ca.py file to the linux server.
7. reset esp32 with the reset pin
8. it should send and receive data over TLS.
