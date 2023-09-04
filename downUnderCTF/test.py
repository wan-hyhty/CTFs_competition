import requests
import pytesseract
import base64
from bs4 import BeautifulSoup
from PIL import Image, ImageOps
import io

url = "https://captcha1.uctf.ir/"
submit_url = "https://captcha1.uctf.ir/"

s = requests.session()
# image_names = []
# for i in range(100):
#     req = s.get('https://captcha2.uctf.ir/')
#     html_content = req.content
#     html_content = BeautifulSoup(html_content, "html.parser")                                       #lay html
#     image_tags = html_content.find_all("img")
#     image_name = [img['src'] for img in image_tags]
#     for img in image_name:
#         if img not in image_names:
#             image_names.append(img)

# print(image_names)
# print(len(image_names))
# https://ctftime.org/task/17320
# [     '9D989E8D27DC9E0EC3389FC855F142C3D40F0C50.jpeg', '148627088915C721CCEBB4C611B859031037E6AD.jpeg',\
#       '09F5EDEB4F5B2A4E4364F6B654682C6758A3FA16.jpeg', 'FF0F0A8B656F0B44C26933ACD2E367B6C1211290.jpeg',\
#       'E49512524F47B4138D850C9D9D85972927281DA0.jpeg', 'C29E4D9C8824409119EAA8BA182051B89121E663.jpeg',\
#       '73335C221018B95C013FF3F074BD9E8550E8D48E.jpeg', '6D0EBBBDCE32474DB8141D23D2C01BD9628D6E5F.jpeg',\
#       '091B5035885C00170FEC9ECF24224933E3DE3FCC.jpeg', '9E05E6832CAFFCA519722B608570B8FF4935B94D.jpeg',\
#       '5ECE240085B9AD85B64896082E3761C54EF581DE.jpeg']

package = {
    '9D989E8D27DC9E0EC3389FC855F142C3D40F0C50.jpeg': 'cat',
    '148627088915C721CCEBB4C611B859031037E6AD.jpeg': 'snake',
    '09F5EDEB4F5B2A4E4364F6B654682C6758A3FA16.jpeg': 'bear',
    'FF0F0A8B656F0B44C26933ACD2E367B6C1211290.jpeg': 'fox',
    'E49512524F47B4138D850C9D9D85972927281DA0.jpeg': 'dog',
    'C29E4D9C8824409119EAA8BA182051B89121E663.jpeg': 'eagle',
    '73335C221018B95C013FF3F074BD9E8550E8D48E.jpeg': 'penguin',
    '6D0EBBBDCE32474DB8141D23D2C01BD9628D6E5F.jpeg': 'rabbit',
    '091B5035885C00170FEC9ECF24224933E3DE3FCC.jpeg': 'horse',
    '9E05E6832CAFFCA519722B608570B8FF4935B94D.jpeg': 'mouse',
    '5ECE240085B9AD85B64896082E3761C54EF581DE.jpeg': 'duck'
}

while True:
    req = s.get('https://captcha2.uctf.ir/')
    html_content = req.content
    html_content = BeautifulSoup(html_content, "html.parser")                                       #lay html
    image_tags = html_content.find_all("img")
    image_name = [img['src'] for img in image_tags]

    res = f"{package[image_name[0]]}-{package[image_name[1]]}"
    print(res)
    captcha = {
        'captcha': res
    }
    req = s.post('https://captcha2.uctf.ir/', data=captcha)
    html_content = req.content
    html_content = BeautifulSoup(html_content, "html.parser")
    score = html_content.find_all('h4')
    print(score[1].text.strip())
    if(html_content.find("You have solved") == -1):
        print(html_content)