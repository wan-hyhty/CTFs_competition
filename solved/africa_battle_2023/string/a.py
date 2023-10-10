from pybraille import transcribe

braille_text = "⠃⠁⠞⠞⠇⠑⠉⠞⠋{⠺⠓⠽⠸⠙⠴⠝⠶⠸⠦⠂⠂⠝⠙⠸⠏⠒⠴⠏⠂⠒⠸⠢⠅⠽⠙⠂⠧⠒⠸⠝⠴⠸⠦⠗⠲⠂⠂⠂⠒⠸⠂⠝⠢⠶⠗⠥⠉⠶⠂⠴⠝⠢}"
decoded_text = transcribe(braille_text)

print(decoded_text)
