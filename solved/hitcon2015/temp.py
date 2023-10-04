import re
import os
import sys
import time
import json
import glob
import datetime
import urllib3
from getpass import getpass
import requests
from pprint import pprint
from pathlib import Path
from bs4 import BeautifulSoup
from selenium import webdriver

base_url = "https://pwnoh.io/login?token=dU2TkBFAPxZ0f2kJ9NF9MLKbHfLKfVQfbe%2FvSBbK%2Bq8IW0D7emMLDBJ%2Fypc8NLSG1UaRjbG3LtOzreeZI8eGD9Cab%2F%2BwIfXTOu31Yf%2FOY%2FaPWy%2BS5kSK6MTP38St"
response = requests.get(base_url)

html = response.text
print(html)


