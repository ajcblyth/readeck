#
#
#
#
#
#
__FALSE__ = 0
__TRUE__  = 1
#
#
#
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0' + hv
        lst.append(hv)
    return reduce(lambda x, y: x + y, lst)
#
#
#
