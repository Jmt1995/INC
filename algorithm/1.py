import  scipy.optimize
from scipy.optimize import linprog
import numpy as np
import gc
import time
def LP_solver(a, b, N, K):

    a_max = max(max(row) for row in a)
    b_max = max(max(row) for row in b)
    maxx = max(a_max, b_max)
    print("max:", maxx)
    i = 0
    while maxx > 0:
        maxx = maxx/10
        i = i+1

    a = [[aaa/(10**(i-1)) for aaa in aa] for aa in a]
    b = [[bbb/(10**(i-1)) for bbb in bb] for bb in b]
    c = gen_c(a, b, N, K)
    # print(c)
    a_equ, b_equ = gen_equ(N, K)
    # print(a_equ, b_equ)
    a_ub, b_ub = gen_ub(N, K, memory)
    # print(a_ub)
    # print(b_ub)

    bounds = gen_bound(N, K)
    print(bounds)
    # res = linprog(c,A_eq=a_equ, b_eq=b_equ, bounds=tuple(bounds))
    res = linprog(c, A_ub=a_ub, b_ub=b_ub, A_eq=a_equ, b_eq=b_equ, bounds=tuple(bounds))
    print(res)
    return res


def gen_c(a, b, N, K):
    print("LP_solver-C-initing")
    m = N*K
    c = list()
    for i in range (0, N):
        for j in range(0, K):
            c.append(m**(a[i][j]+b[i][j])-1)
    return c
def gen_equ(N, K):
    print("LP_solver-equ-initing")
    a_equ = list()
    b_equ = list()
    for i in range (0, N):
        item = [0]  * i * K + [1] * K + [0]  * (N - i - 1)*K
        a_equ.append(item)
        b_equ.append(1)
    return a_equ, b_equ

def gen_ub(N, K, memory):
    print("LP_solver-ub-initing")
    a_ub = list()
    b_ub = list()
    for j in range (0, K):
        item  = list()
        for i in range(0, N*K):
            item.append(0)
        a_ub.append(item)
    for j in range (0, K):
        for i in range(0, N):
            a_ub[j][i*N + j] = 1
        b_ub.append(memory[i])
    return a_ub, b_ub

def gen_bound(N, K):
    print("LP_solver-bound-initing")
    bounds = list()
    for i in range (0, N):
        for j in range(0, K):
            bounds.append([0, 1])
    return bounds

if __name__ == '__main__':
    #
    N = 1;
    K = 10;
    #
    a = [[3, 3, 4, 4, 4, 4, 4, 5, 5, 5 ]]
    b = [[3, 3, 4, 4, 2, 2, 4, 5, 2, 1 ]]

    # a = [[30, 3, 4, 4, 4 ]]
    # b = [[3, 30, 1, 3, 2 ]]

    # print a
    # a = [[5, 0.5, 0.4, 0.4, 0.4]]
    # b = [[0.3, 0.3, 0.4, 0.4, 0.2 ]]
    memory = [128, 128, 128, 128, 128, 128, 128, 128, 128, 128]

    res = LP_solver(a, b, N, K)

    if res.x[0] == 1:
        print "res:", res.x[0]
    else:
        print "error"








    # b = 5
    # C = [-1,4]
    # A = [[-3,1],[1,2]]
    # b = [6,4]
    # X0_bounds = [None,None]
    # X1_bounds = [-3,None]
    # res = linprog(C,A_ub= A, b_ub = b, bounds=(X0_bounds,X1_bounds))
    # print(res)


