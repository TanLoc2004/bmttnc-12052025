def truy_cap_phan_tu(tuple):
    first_element = tuple[0]
    last_element = tuple[-1]
    return first_element, last_element
        
input_tuple = eval(input("Nhập một tuple (ví dụ: (1, 2, 3)): "))
first, last = truy_cap_phan_tu(input_tuple)     

print("Phần tử đầu tiên:", first)
print("Phần tử cuối cùng:", last)
        
        
        
        