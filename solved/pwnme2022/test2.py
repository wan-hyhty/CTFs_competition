p = "0b1212120202020202121212020202121212120202120212121212120202020212021212120212021202121202020212121202120212121202020212121212021202121202121202120212121202020212020202021212121202020212021202121212121212021202021212120212021212020212020212020202121212121202121202021202021202120202020212120212021212121202020212121202121202021212021212020212120212020212121212020202021202021212021212121202021202121202020202121202020212120202121212021202020212020212021202121202021212021212120212121212021212021202120202021202021202020212120212120212120212021212021212121212020212021212121212121212021212020212121212021212020202121202120212021212021202121212021212021212121212120202021212121212020212021202121212121202020212021202020202120212120202120212021202020212121202120212120202020202121202021212120202120202120202120202020212020212021212021202021202020202120212120202121212020202120212020202020202121212121202121212120212021202121202021212120212120212120202021202121202121202021202021202121202020202120202120202021212120212120212120202"
q = ""
p_f = []
for digit in p[2:]:
    if digit == '0' or digit == '1' or digit == '2':
        p_f.append(int(digit))
count = 0
for num in p_f:
    if num == 2:
        count += 1

p_2 = "1"
for i in range(count):
    p_2 += "0"
p_2 = int(p_2, 2)

p_t = []
print(count)
count_brute = 0
for _ in range(0, 2 ** count):
    temp = p_2
    p_t = p_f[:]
    for i in range(len(p_f)-1, -1, -1):
        if (p_t[i] == 2):
            p_t[i] = temp & 0b1
            temp = temp >> 1
        i -= 1
    p_2 += 1
    p_str = "0b"+''.join(str(i) for i in p_t)
    p_res = int(p_str, 2)

    if 27827431791848080510562137781647062324705519074578573542080709104213290885384138112622589204213039784586739531100900121818773231746353628701496871262808779177634066307811340728596967443136248066021733132197733950698309054408992256119278475934840426097782450035074949407003770020982281271016621089217842433829236239812065860591373247969334485969558679735740571326071758317172261557282013095697983483074361658192130930535327572516432407351968014347094777815311598324897654188279810868213771660240365442631965923595072542164009330360016248531635617943805455233362064406931834698027641363345541747316319322362708173430359 % p_res == 0:
        print("p: ", 27827431791848080510562137781647062324705519074578573542080709104213290885384138112622589204213039784586739531100900121818773231746353628701496871262808779177634066307811340728596967443136248066021733132197733950698309054408992256119278475934840426097782450035074949407003770020982281271016621089217842433829236239812065860591373247969334485969558679735740571326071758317172261557282013095697983483074361658192130930535327572516432407351968014347094777815311598324897654188279810868213771660240365442631965923595072542164009330360016248531635617943805455233362064406931834698027641363345541747316319322362708173430359 / p_res)
        print("q: ", p_res)
        break
    else:
        count_brute += 1
        print(count_brute)