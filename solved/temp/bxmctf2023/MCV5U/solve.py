import numpy as np

SIZE = int(3e5)
VERIFY_KEY = "46e1b8845b40bc9d977b8932580ae44c"

def getSequence(A, B, n, m):
    # Tính tích hai ma trận bằng Strassen Algorithm
    # Tạo ma trận kết quả mới với dtype giống với ma trận A
    C = np.zeros(n + m - 1, dtype=np.int64)
    np.convolve(A, B, out=C)
    return C

# Ma trận ban đầu
A = [0] * SIZE
B = [0] * SIZE

document1 = open("Document 1.txt", "r")
nums1 = document1.readlines()

idx = 0

for num in nums1:
    A[idx] = int(num.strip())
    idx += 1

document2 = open("Document 2.txt", "r")
nums2 = document2.readlines()

idx = 0

for num in nums2:
    B[idx] = int(num.strip())
    idx += 1

# Gọi hàm getSequence để tính tích hai ma trận
sequence = getSequence(np.array(A), np.array(B), SIZE, SIZE)

# In kết quả
print(sequence)