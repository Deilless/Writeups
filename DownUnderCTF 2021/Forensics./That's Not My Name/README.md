# Writeup for the challenge **_`That's Not My Name`_** from DownUnder CTF 2021
----

- ## Challenge Information:

| - | - |
| ----------- | ----------- |
| Name: | **`That's Not My Name`** |
| Category: | **`forensics`** |
| Points: | **`100pts`**|
| Author: | **`Conletz`**|

- ## Description :
 I think some of my data has been stolen, can you help me?

---

- ## Solution

This challenge gives us a network capture in .pcap format.

First step is to open the file with wireshark to analyze the network capture content.

![Capture 1](https://github.com/Deilless/Writeups/blob/b6aef88cf16c2130cd1167f3527016183b475f39/Images/notmyname1.png)

As we can expect there are a ton of frames...

The best way to have a quick overview of the network capture is to go into Statistics -> protocol hierarchy.
![Capture 2](https://github.com/Deilless/Writeups/blob/b6aef88cf16c2130cd1167f3527016183b475f39/Images/notmyname2.png)

![Capture 3](https://github.com/Deilless/Writeups/blob/b6aef88cf16c2130cd1167f3527016183b475f39/Images/notmyname3.png)

The first thing we note is the suspiciously large amount of Domain Name System (DNS) frames which directly echoes the name of the challenge "That's not my **name**".

We then filter frames by DNS protocol.

![Capture 4](https://github.com/Deilless/Writeups/blob/b6aef88cf16c2130cd1167f3527016183b475f39/Images/notmyname4.png)

And after a quick review of the frames we found those pretty suspicious frames, every frame is encrypted which is quite unusual and their length is easily the double of others DNS frames.

![Capture 5](https://github.com/Deilless/Writeups/blob/b6aef88cf16c2130cd1167f3527016183b475f39/Images/notmyname5.png)

We then follow the UDP stream to see how much and what data is being exchanged in this stream.

![Capture 6](https://github.com/Deilless/Writeups/blob/b6aef88cf16c2130cd1167f3527016183b475f39/Images/notmyname6.png)

And the result is, again, very interesting. If we compare two UDP streams of DNS requests we can clearly see that there is a lot of data transferred. 

![Capture 7](https://github.com/Deilless/Writeups/blob/b6aef88cf16c2130cd1167f3527016183b475f39/Images/notmyname7.png)
*left window is the UDP stream of a normal dns query, right window is the UDP stream of the suspicious query*

In addition to the encoded data in the stream, the domain is suspiciously named `qawesrdtfgyhuj.xyz`, this detail will be useful later.

The amount of data in this stream is massive and encoded, we'll need some tools to see what's hidden in it.

---
### Deciphering the stream

As we saw previously, we have a massive amount of encoded data in a UDP stream, we can extract it with a simple command, thanks to tshark.

```tshark -r notmyname.pcapng -Tfields -e dns.qry.name > dns.txt```

This command will dump every DNS packet in a text file, ready to be deciphered.
A quick try on [CyberChef](https://gchq.github.io/CyberChef) will confirm that these packets are encoded in hex

![Capture 8](https://github.com/Deilless/Writeups/blob/b6aef88cf16c2130cd1167f3527016183b475f39/Images/notmyname8.png)

Next I use [XPN's python script](https://blog.xpnsec.com/bsidessf-dnscap/) to filter out the uninteresting DNS packets and decipher what's left and dump the result in our standard output. As you can see, the packets are filtered by domain name, that's where we exploit our previous observation. 

```python
import re
import binascii

with open('dns.txt', 'r') as f:
    for name in f:
        m = re.findall('([a-z0-9\.]+)\.qawesrdtfgyhuj.xyz', name)
        if m:
            print binascii.unhexlify(m[0].replace('.', '')) 
```

We then execute the script :

``python2 crypt.py > dump.txt``

and we extract the ASCII characters with `strings` :

``strings dump.txt``

there are still are ton of lines in the output so we will pipe some grep in the next command :

``strings dump.txt | grep DUCTF``

and the output :
```
DUCTF{c4t_g07_y0ur_n4m3}
DUCTF{c4t_g07_y0ur_n4m3}
```
