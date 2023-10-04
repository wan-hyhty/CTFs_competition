import jinja2
from flask import Flask, flash, redirect, render_template, request, session, abort

mail = """
Hello team,

A new hacker wants to join our private Bug bounty program! Mary, can you schedule an interview?

 - Name: {{ hacker_name }}
 - Surname: {{ hacker_surname }}
 - Email: {{ hacker_email }}
 - Birth date: {{ hacker_bday }}

I'm sending you the details of the application in the attached CSV file:

 - '{{ hacker_name }}{{ hacker_surname }}{{ hacker_email }}{{ hacker_bday }}.csv'

Best regards,
"""

def sendmail(address, content):
    try:
        content += "\n\n{{ signature }}"
        _signature = """---\n<b>Offsec Team</b>\noffsecteam@hackorp.com"""
        content = jinja2.Template(content).render(signature=_signature)
    except Exception as e:
        pass
    return None

def sanitize(value):
    blacklist = ['{{','}}','{%','%}','import','eval','builtins','class','[',']']
    for word in blacklist:
        if word in value:
            value = value.replace(word,'')
    if any([bool(w in value) for w in blacklist]):
        value = sanitize(value)
    return value

app = Flask(__name__, template_folder="./templates/", static_folder="./static/")
app.config['DEBUG'] = False

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

@app.route("/", methods=['GET','POST'])
def register():
    global mail
    if request.method == "POST":
        if "name" in request.form.keys() and len(request.form["name"]) != 0 and "surname" in request.form.keys() and len(request.form["surname"]) != 0 and "email" in request.form.keys() and len(request.form["email"]) != 0 and "bday" in request.form.keys() and len(request.form["bday"]) != 0 :
            if len(request.form["name"]) > 20:
                return render_template("index.html", error="Field 'name' is too long.")
            if len(request.form["surname"]) >= 50:
                return render_template("index.html", error="Field 'surname' is too long.")
            if len(request.form["email"]) >= 50:
                return render_template("index.html", error="Field 'email' is too long.")
            if len(request.form["bday"]) > 10:
                return render_template("index.html", error="Field 'bday' is too long.")
            try:
                register_mail = jinja2.Template(mail).render(
                    hacker_name=sanitize(request.form["name"]),
                    hacker_surname=sanitize(request.form["surname"]),
                    hacker_email=sanitize(request.form["email"]),
                    hacker_bday=sanitize(request.form["bday"])
                )
            except Exception as e:
                pass
            sendmail("offsecteam@hackorp.com", register_mail)
            return render_template("index.html", success="Thank you! Your application will be reviewed within a week.")
        else:
            return render_template("index.html", error="Missing fields in the application form!")
    elif request.method == 'GET':
        return render_template("index.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=59073)