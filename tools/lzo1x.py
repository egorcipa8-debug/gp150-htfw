def lzo1x_decompress(src, max_out=64*1024*1024):
    op = bytearray(); ip = 0; n = len(src)
    def lit(t):
        nonlocal ip
        op.extend(src[ip:ip+t]); ip += t
    def cpy(mpos, cnt):
        for _ in range(cnt):
            op.append(op[mpos]); mpos += 1
    state = 'start'; t = 0
    if src[0] > 17:
        t = src[0] - 17; ip = 1
        if t < 4: state = 'match_next'
        else:
            lit(t); state = 'first_literal_run'
    else:
        state = 'loop'
    while True:
        if len(op) > max_out: raise ValueError('output too large')
        if state == 'loop':
            if ip >= n: break
            t = src[ip]; ip += 1
            if t >= 16: state = 'match'; continue
            if t == 0:
                while src[ip] == 0: t += 255; ip += 1
                t += 15 + src[ip]; ip += 1
            lit(t + 3); state = 'first_literal_run'; continue
        if state == 'first_literal_run':
            t = src[ip]; ip += 1
            if t >= 16: state = 'match'; continue
            mpos = len(op) - (1 + 0x0800) - (t >> 2) - (src[ip] << 2); ip += 1
            if mpos < 0: raise ValueError('bad back-ref (flr)')
            cpy(mpos, 3); state = 'match_done'; continue
        if state == 'match':
            if t >= 64:
                mpos = len(op) - 1 - ((t >> 2) & 7) - (src[ip] << 3); ip += 1
                t = (t >> 5) - 1
            elif t >= 32:
                t &= 31
                if t == 0:
                    while src[ip] == 0: t += 255; ip += 1
                    t += 31 + src[ip]; ip += 1
                mpos = len(op) - 1 - (src[ip] >> 2) - (src[ip+1] << 6); ip += 2
            elif t >= 16:
                mpos = len(op) - ((t & 8) << 11)
                t &= 7
                if t == 0:
                    while src[ip] == 0: t += 255; ip += 1
                    t += 7 + src[ip]; ip += 1
                mpos -= (src[ip] >> 2) + (src[ip+1] << 6); ip += 2
                if mpos == len(op): break          # EOF marker
                mpos -= 0x4000
            else:
                mpos = len(op) - 1 - (t >> 2) - (src[ip] << 2); ip += 1
                if mpos < 0: raise ValueError('bad back-ref (m1)')
                cpy(mpos, 2); state = 'match_done'; continue
            if mpos < 0: raise ValueError('bad back-ref (match)')
            cpy(mpos, t + 2); state = 'match_done'; continue
        if state == 'match_done':
            t = src[ip-2] & 3
            if t == 0: state = 'loop'; continue
            state = 'match_next'; continue
        if state == 'match_next':
            lit(t)
            if ip >= n: break
            t = src[ip]; ip += 1
            state = 'match'; continue
    return bytes(op)
