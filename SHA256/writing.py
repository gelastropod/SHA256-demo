file = open("in.txt", "a")
for i in range(100):
    file.write("a" * 10000)
