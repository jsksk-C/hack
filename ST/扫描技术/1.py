sum = 321
num = []
b = 1
while sum>0:
    a = sum%10*b
    num.append(a)
    sum = sum//10
    b = b*10

print(num)