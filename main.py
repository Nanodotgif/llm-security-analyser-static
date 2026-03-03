import sys
import extractor

if len(sys.argv) != 3:
    print("[Error]: Invalid number of arguments")

print(sys.argv[1] + " " + sys.argv[2])
if not (extractor.verify_input_pdf(sys.argv[1]) and extractor.verify_input_pdf(sys.argv[2])):
    quit(-1)

print("Documents validated.")