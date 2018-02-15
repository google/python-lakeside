Python control for Eufy LED bulbs
=================================

A simple Python API for controlling LED bulbs from [Eufy](https://www.eufylife.com/).

Example use
-----------

This will connect to a bulb and turn it on at 50% brightness and the hottest colour temperature.
```
import lakeside

bulb = lakeside.bulb(ip_address, access_code)
bulb.connect()
bulb.set_state(power=True, brightness=50, temperature=100)
```

The ip and access code can be obtained by doing:

```
import lakeside

devices = lakeside.get_devices(username, password)
```

where username and password are the credentials used in the Eufy app.

This is not an officially supported Google project.
