from Crypto.Hash import SHA256
from urllib.parse import quote_from_bytes

signature = '5816211e284ab224a1f6988f06f4643006ede4d913a49b352dd0d1dd1181c207'
hashed_m = 'O%3A4%3A%22User%22%3A2%3A%7Bs%3A15%3A%22%00User%00userlevel%22%3Bi%3A10%3Bs%3A14%3A%22%00User%00username%22%3Bs%3A8%3A%22John+Doe%22%3B%7D%3Cx%3EO%3A4%3A%22User%22%3A2%3A%7Bs%3A15%3A%22%00User%00userlevel%22%3Bi%3A33%3Bs%3A14%3A%22%00User%00username%22%3Bs%3A12%3A%22Peter+Parker%22%3B%7D%3Cx%3EO%3A4%3A%22User%22%3A2%3A%7Bs%3A15%3A%22%00User%00userlevel%22%3Bi%3A87%3Bs%3A14%3A%22%00User%00username%22%3Bs%3A11%3A%22Gabe+Newell%22%3B%7D'

padding     = '80000000000000000000000000000000000000000000000000'
byte_length = '00000000000008f8'
append = '%3Cx%3EO%3A4%3A%22User%22%3A2%3A%7Bs%3A15%3A%22%00User%00userlevel%22%3Bi%3A2107%3Bs%3A14%3A%22%00User%00username%22%3Bs%3A11%3A%22Gabe+Newell%22%3B%7D'

h_prime = SHA256.new(data=bytes.fromhex(signature))
h_prime.update(str.encode(append))
print('new signature: %s' % h_prime.hexdigest())
print('new message: %s' % (hashed_m + quote_from_bytes(bytes.fromhex(padding + byte_length)) + append))