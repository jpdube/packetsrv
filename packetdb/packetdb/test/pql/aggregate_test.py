
from app.pql.aggregate import Count, Max, Min, Sum


def test_class_name():
    s = Sum("frame,inc_len", "ttl_bytes")
    print(s)

    c = Count("frame,inc_len", "ttl_bytes")
    print(c)

    minn = Min("frame,inc_len", "ttl_bytes")
    print(minn)

    maxx = Max("frame,inc_len", "ttl_bytes")
    print(maxx)

def test_count():
    cnt = Count("ip.dst", "frame_count")
    
    count_list = []
    for i in range(5):
        count_list.append(None)

    print(cnt.execute(count_list))