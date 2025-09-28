# APEX Server Deployment Guide (for Raspberry Pi)

## Description
Hey! This guide will walk you through setting up the APEX social network server on your Raspberry Pi so that anyone in the world can access it.

## Features
We'll be doing three main things:

Setting up the Raspberry Pi with the necessary software.

Configuring Your Home Router to allow traffic from the internet to reach the Pi.

Finding Your Public IP Address so people know where to connect.

## Important Note
This guide is for turning a home computer into a live web server. This is awesome, but be aware of the security implications. Make sure the Raspberry Pi doesn't have any sensitive personal files on it.

# Steps
Step 1: Prepare the Raspberry Pi
First, we need to get the Pi ready to run the Python server.

1.1. Install Required Software
Open a terminal window on your Raspberry Pi and run these commands one by one.

## Update the package list
sudo apt-get update

## Install Python, the package manager (pip), and a virtual environment tool
sudo apt-get install python3 python3-pip python3-venv -y

1.2. Get the Code
You'll need the server.py and index.html files from ssamjjang. Create a new folder for the project and place them inside.

## Create a new folder for the app
mkdir apex-server
cd apex-server

Now, place the server.py and index.html files inside this folder.
You can use a USB drive, SCP, or any method you prefer.

1.3. Set Up a Virtual Environment
This is best practice for any Python project. It keeps all the required libraries isolated.

## Create the virtual environment
python3 -m venv venv

## Activate it (you'll need to do this every time you open a new terminal)
source venv/bin/activate

You'll know it's working if your terminal prompt changes to show (venv).

1.4. Install Python Libraries
Now, install all the libraries the server needs to run.

pip install Flask Flask-SQLAlchemy Flask-SocketIO Flask-Cors Authlib Pillow pytz

Step 2: Configure Your Home Router (Port Forwarding)
This is the most critical step. Your router acts as a gatekeeper for your home network. By default, it blocks all incoming traffic from the internet for security. We need to tell it to "forward" any web traffic directly to your Raspberry Pi.

2.1. Find the Raspberry Pi's Local IP Address
You need to know the Pi's address on your local network.

# Run this command in the Pi's terminal
hostname -I

This will output an IP address. It will probably look something like 192.168.1.15 or 10.0.0.25. Write this address down. This is your Pi's Local IP.

2.2. Log In to Your Router
Find your router's login address (it's usually 192.168.1.1 or 192.168.0.1).

Open a web browser on any computer connected to your WiFi and go to that address.

Log in with your router's admin username and password. (Often printed on a sticker on the router itself).

2.3. Set Up the Port Forwarding Rule
Every router's interface is different, but you are looking for a section named "Port Forwarding," "Virtual Server," or "NAT."

You need to create a new rule with the following settings:

Service Name / Application Name: APEX Server (or whatever you want)

Port Range / External Port: 5000

Internal Port: 5000

Device IP / Internal IP Address: Enter the Pi's Local IP you wrote down in step 2.1.

Protocol: TCP (or TCP/UDP if that's the only option)

Enable/Status: Make sure the rule is enabled.

Save or Apply the new rule. This tells your router: "If any computer from the internet tries to connect to my network on port 5000, send that connection directly to the Raspberry Pi."

Step 3: Run the Server and Go Live!
Now you're ready to start the server and find your public address.

3.1. Start the APEX Server
In your Raspberry Pi terminal, make sure you are in the apex-server directory and that your virtual environment is active.

## If you opened a new terminal, reactivate the environment first:
## source venv/bin/activate

# Run the server!
python3 server.py

If everything is correct, you will see output indicating that the server is running on 0.0.0.0:5000. It is now live on your local network and waiting for connections from the internet.

3.2. Find Your Public IP Address
This is the address the rest of the world will use to connect to your server.

On the Raspberry Pi (or any computer on the same network), open a web browser and go to Google.

Search for "what is my ip address".

Google will show you your Public IP Address. It will be a different set of numbers (e.g., 203.0.113.55).

3.3. Connect from the Outside World!
You can now give this Public IP Address to ssamjjang and your friends. They should be able to access the APEX website by going to:

http://<YOUR_PUBLIC_IP_ADDRESS>:5000

For example: http://203.0.113.55:5000

That's it! Your Raspberry Pi is now a live web server for the APEX project.