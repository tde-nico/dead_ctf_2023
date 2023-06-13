from Crypto.Util.number import GCD, bytes_to_long, long_to_bytes
import gmpy2
import binascii
from functools import reduce

with open('really-loud-output.txt', 'r') as f:
	data = f.readlines()

ps = eval(data[0])
S = eval(data[1])

def crt(a, n):
	sum = 0
	prod = reduce(lambda x, y: x*y, n)
	for n_i, a_i in zip(n, a):
		p = prod // n_i
		sum += a_i * gmpy2.invert(p, n_i) * p
	return sum % prod


for a in range(10):
	for b in range(10):
		for c in range(10):
			for d in range(10):
				if crt([S[0][a], S[1][b], S[2][c], S[3][d]], ps[0:4]) < 2**2048:
					print(a, b, c, d, crt([S[0][a], S[1][b], S[2][c], S[3][d]], ps[0:4]))
					exit()

# 1 5 5 4 31638818418853078181649864376077883964278482051227593353676799652922219184064885435633612151816067267472450398119942365176290962664655592150763500085550148021333142557520201007351742989736302212052763950802275605844080214700453006127672112644483037579375786169343774257817731543264471698224896835340829018822535523018596478456422420125863504209512643044942820023479937882864374186052109604985037140887393271805397537218393358080586009282592023976592035434790072827379995198387039033415010213074681614709647184370784802396779738407385889673372815359773101543636797177847395463022542407449627376305019833575664992027926
