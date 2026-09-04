# model/mlkem/ntt.py

Q = 3329
N = 256
ZETA = 17
INV_N = pow(128, -1, Q)

def bit_rev_7(i: int) -> int:
    """Reverse the low 7 bits of i (0..127)."""
    r = 0
    for _ in range(7):
        r = (r << 1) | (i & 1)
        i >>= 1

    return r 

def make_zetas():
    """Build the 128-entry twiddle table: ZETAS[i] = 17^bit_rev_7(i) mod 3329."""
    #one line inside a list comprehension, using pow(base, exp, mod)
    zetas=[]
    for i in range(128):
        zetas.append(pow(ZETA,bit_rev_7(i),Q))
    return zetas

ZETAS = make_zetas()

def add_mod(a, b):
    c = (a+b)%Q 
    return c

def sub_mod(a, b):
    c= (a-b)%Q
    return c

def mul_mod(a, b):
    c= (a*b)%Q  
    return c

def ntt(poly):
    """Forward NTT. poly: list of 256 ints. Returns new list of 256 ints."""
    a = poly[:]              # work on a copy, don't mutate caller's list
    k = 1                    # index into ZETAS — increments once per butterfly, across ALL pairs in a stage
    for stage in range(7):
        stride = 1 << (7 - stage)   
        for start in range(0, 256, 2 * stride):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + stride):
                # the butterfly itself
                t = mul_mod(zeta, a[j + stride])
                a[j + stride] = sub_mod(a[j], t)
                a[j] = add_mod(a[j], t)
                pass
    return a

def intt(poly):
    """Inverse NTT: structural mirror of ntt(), stages walked in the opposite
    order, plus final scaling by INV_N = pow(128, -1, Q)."""
    a = poly[:]             
    k = 127 
    
    for stage in range(7):
        stride = 1 << (stage+1)   
        for start in range(0, 256, 2 * stride):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + stride):
                t = a[j]
                a[j]= add_mod(t, a[j + stride])
                a[j + stride] = mul_mod(zeta, sub_mod(a[j + stride], t))
    for i in range(256):
        a[i]= mul_mod(a[i],INV_N)            
    return a

if __name__ == "__main__":
    import random
    for _ in range(100):
        p = [random.randrange(Q) for _ in range(N)]
        assert intt(ntt(p)) == p, "identity property failed"
    print("NTT/INTT identity check passed on 100 random polynomials")