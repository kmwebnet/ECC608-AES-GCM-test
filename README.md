# ECC608-AES-GCM-Test

This tests AES-GCM function by storing and using key at ATECC608 secret slot.  
all of components for running AES-GCM command will store into ATECC608's slot 8.   

IV(12byte) ,tag(16)bytes ,to be crypted data (240)bytes

this is ideal to store secret information inside the device securely by prohibiting AES key access.

# Requirements

  Platformio with VS Code environment.  
  install "Espressif 32" platform definition on Platformio
  configure ATECC608 slot 5 to work with AES command properly.

# Environment reference
  
  Espressif ESP32-DevkitC  
  this project initializes both of I2C 0,1 port, and the device on I2C port 0 is absent.  
  pin assined as below:  


      I2C 0 SDA GPIO_NUM_18
      I2C 0 SCL GPIO_NUM_19

      I2C 1 SDA GPIO_NUM_21
      I2C 1 SCL GPIO_NUM_22
          
  Microchip ATECC608(on I2C port 1)  

# Usage

"git clone --recursive <this pages URL>" on your target directory.  
you need to change a serial port number which actually connected to ESP32 in platformio.ini.

# Run this project

just execute "Upload" on Platformio.   

# License

This software is released under the MIT License, see LICENSE.
