import requests
import pytesseract
import base64
from bs4 import BeautifulSoup
from PIL import Image, ImageOps
import io

url = "http://localhost:1337/"
submit_url = "http://localhost:1337/submit"

# pytesseract.pytesseract.tesseract_cmd = r'/mnt/d'
s = requests.session()
for i in range(1):
    req = s.get('http://localhost:1337/')

    req_html = (req.text)                                       #lay html
    start_index = req_html.find('base64,') + len('base64,')     #lay base64 cua captcha
    end_index = req_html.find('" alt=')
    base64_data = req_html[start_index:end_index]
    image_data = base64.b64decode(base64_data)                  #decode base 64
    img = Image.open(io.BytesIO(image_data))                    
    data = pytesseract.image_to_string(
        img, config='--psm 6 --oem 3 -l eng -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ')[:-2]    #doc hinh anh

    captcha = {
        'captcha': data
    }

    r = s.post(submit_url, data=captcha)                        #gui hinh anh
    html_content = r.content                                    #lay html
    soup = BeautifulSoup(html_content, "html.parser")           #lam cho no dep hon =)))
    text_score = soup.h3.text.strip()                           #lay <h3>
    print(text_score)

    if (text_score.find("100") != -1):
        print(soup)
        break
# https://ctftime.org/task/17320
#
#