# Ma trận ban đầu
A = np.array([[1, 2], [3, 4]])
B = np.array([[5, 6], [7, 8]])

# Tính tích hai ma trận bằng Strassen Algorithm
n = max(A.shape[0], A.shape[1], B.shape[1])
n = int(2 ** np.ceil(np.log2(n)))
C = np.zeros((n, n))
np.dot(A, B, out=C)

# In kết quả
print(C[:A.shape[0], :B.shape[1]])