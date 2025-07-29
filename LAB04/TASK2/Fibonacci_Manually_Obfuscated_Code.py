def a1(x):
    if x <= 0:
        return 0
    elif x == 1:
        return 1
    else:
        return a1(x - 1) + a1(x - 2)

print(a1(7))
