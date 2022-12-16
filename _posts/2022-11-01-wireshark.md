# Wireshark Practice (Difficulty: 🎄)
In this challenge we are given an pcap file that we must answer some questions about. The extention `.pcap` stands for packet capture.
Its a file that stores infomation about all the data that goes in and out of specific computer. They are incredibly helpful for 
computer forensics and typically we use a tool called wireshark to analyze these. Each task of the challenge is explained below:

## Prompt 1
`There are objects in the PCAP file that can be exported by Wireshark and/or Tshark. What type of objects can be exported
from this PCAP?`

### Solution
A quick google search told me we can extract objects in wireshark by going to `File -> Extract Objects -> 𝘛𝘺𝘱𝘦 𝘰𝘧 𝘰𝘣𝘫𝘦𝘤𝘵`
This brings up a popup with all the objects of that type.

![](/img/wireshark_objects.png)
Clicking through the different options shows us that there are objects under the `HTTP` type, so thats what we submit to the termial.

## Prompt 2
`What is the file name of the largest file we can export?`

### Solution
![](/img/wireshark2.png)
This is the list of exportable objects from the menu described above. There we see the largest file is `808kb` and called `app.php`

## Prompt 3
`What packet number starts that app.php file?`

### Solution
Again referenceing the above screenshot, we can see packet 687 is our our starting point.
 
## Prompt 4
`What is the IP of the Apache server?`
 
## Solution
To get this one, we need to actually start looking at the packets themselves. Since we know this is a packet capture of an http
interaction between a client computer and a server computer, we can tell wireshark to only show us http packets. We do this with
what's called a display filter. In the display filter box at the top of the program we can simply type `http` and then `ENTER`.
![](/img/wireshark_display.png)
Since GET requests are made by the client to the server, the destination address of the GET request packets must be our server.
This means our Apache server is located at `192.185.57.242`.
 
## Prompt 5
`What file is saved to the infected host?`

## Solution
This task is a bit tricky. We may be tempted to say `app.php`, after all, isn't that what the client asked for in the GET request?
Well not quite. Making a get request to a php file setup on a webserver triggers the backend to run the php code. We have to
inspect the web traffic more carefully to see whats going on. A nice way of viewing a conversation between two computers in wireshark
is to look at a specific stream of data. If we right click our starting http packet and go to `follow -> HTTP Stream`. 
![](/img/stream_menu.png)
This gives us a nice view of the http requests and responses between the two computers. Scrolling through we see some javacode is
loaded and run on the victims computer. At the end of this code we see the following code
``` javascript
let byteNumbers = new Array(byteCharacters.length);
for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
}
let byteArray = new Uint8Array(byteNumbers);

// now that we have the byte array, construct the blob from it
let blob1 = new Blob([byteArray], {type: 'application/octet-stream'});

saveAs(blob1, 'Ref_Sept24-2020.zip');
```
Here it becomes clear that a payload is getting saved to the file `Ref_Sept24-2020.zip`.

## Prompt 6
`Attackers used bad TLS certificates in this traffic. Which countries were they registered to? Submit the names of the countries in
alphabetical order seperated by commas (Ex: Norway, South Korea).`

## Solution


