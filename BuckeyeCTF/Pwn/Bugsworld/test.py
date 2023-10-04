import random
import time
from randcrack import RandCrack

def test_submit_too_much():
    # random.seed(time.time())

    cracker = RandCrack()

    for i in range(624):
        cracker.submit(random.randint(0, 4294967294))

    print("Random result: {}\nCracker result: {}"
    .format(random.randrange(0, 4294967295), cracker.predict_randrange(0, 4294967295)))
    print("Random result: {}\nCracker result: {}"
    .format(random.randrange(0, 4294967295), cracker.predict_randrange(0, 4294967295)))
test_submit_too_much()