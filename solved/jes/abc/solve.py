# importing the "tarfile" module
import tarfile

# open file
i = -2
while i > -1000:
    file = tarfile.open(f'file{i}.tar.gz')

    # extracting file
    file.extractall()

    file.close()
    i -= 1
