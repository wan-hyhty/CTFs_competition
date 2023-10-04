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


def create_dir(path):
    try:
        if not os.path.exists(path):
            os.mkdir(path)
            print("%s created" % path)
    except OSError:
        print("Error creating %s" % path)


def find_ctf_dir(ctf_name):
    if ctf_name in os.getcwd():
        dirs = os.getcwd().split("/")
        for i, v in enumerate(dirs):
            if v == ctf_name:
                ctf_dir = ""
                for x in range(i + 1):
                    if dirs[x] != "":
                        ctf_dir = ctf_dir + "/" + dirs[x]
                return ctf_dir
    print("Please run in the CTF directory otherwise run setup first!")
    exit()


def get_challs(session, token):
    print("a")


def login(session, base_url, token):

    print(token)
    re = session.get(token)
    print(re.text)
    if re.status_code == 200:
        print("Truy cập thành công")
    else:
        print("Truy cập thất bại")


def setup(path):
    create_dir(path)
    print("CTF Folder created!")
    if not os.path.exists(path / "readme.md"):
        open(path / "readme.md", "a").close()
    os.system("git init " + str(path))
    exit()


if __name__ == "__main__":
    try:
        base_url = sys.argv[1]
        token = sys.argv[2]
        action = sys.argv[3]
        ctf_name = base_url.replace("https://", "").replace(".", "_")

        s = requests.Session()
        ctf_dir = find_ctf_dir(ctf_name)
        ctf_path = Path(ctf_dir)
        login(s, base_url, token)

        if action == "setup":
            path = os.getcwd()
            ctf_path = Path(path + "/" + ctf_name)
            setup(ctf_path)
        elif action == "challs":
            get_challs(s, token)
    except KeyboardInterrupt:
        print("\nExiting...")
        exit()
