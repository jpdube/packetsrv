from datetime import datetime

def binarySearch(v, To_Find):
    lo = 0
    hi = len(v) - 1
    nbr_interactions = 0 
    # This below check covers all cases , so need to check
    # for mid=lo-(hi-lo)/2
    while hi - lo > 1:
        nbr_interactions += 1
        mid = (hi + lo) // 2
        if v[mid] < To_Find:
            lo = mid + 1
        else:
            hi = mid
 
    if v[lo] == To_Find:
        print("Found At Index", lo, nbr_interactions)
    elif v[hi] == To_Find:
        print("Found At Index", hi, nbr_interactions)
    else:
        print("Not Found", nbr_interactions)
 
 
if __name__ == '__main__':
    v = []
    for i in range(1_000_000_000):
        v.append(int(i))
 
    # To_Find = 1
    # binarySearch(v, To_Find)

 #    To_Find = 1_233_867
 #    binarySearch(v, To_Find)
 # 
 #    To_Find = 13_896
 #    binarySearch(v, To_Find)
 
    start_time = datetime.now()
    To_Find = 234_100
    binarySearch(v, To_Find)
    To_Find = 999_000_000
    binarySearch(v, To_Find)
    To_Find = 500_000_000
    binarySearch(v, To_Find)
    print(f"---> Total Time: {(datetime.now() - start_time)}")
