# coding: UTF-8

# (1)
DEADCODE = b'E8000000005883C006FFE0'.decode('hex')
# (2)
text_start = text_end = None
for ea in Segments():
    if SegName(ea) == '.text':
        text_start = ea
        text_end = SegEnd(ea)
        break

# (3)
text = GetManyBytes(text_start, text_end − text_start)

# (4)
pos = text.find(DEADCODE)
while pos != −1:
    for i in range(len(DEADCODE)):
        PatchByte(text_start + pos + i, 0x90)
    pos = text.find(DEADCODE, pos + len(DEADCODE))

# (5)
funcs = tuple(Functions(text_start, text_end)) MakeUnknown(text_start, text_end − text_start, DOUNK_SIMPLE) AnalyzeArea(text_start, text_end)
for f in funcs:
    MakeFunction(f, BADADDR)
