import json, os, subprocess, tempfile, sys, re
sys.path.insert(0, '.')
from a4.core.inspection_data import InspectionData

host = './workspace/output/target/release/risc0-host'
args = ['--in1', '5', '--in4', '10']
print('Running inspection...')
data = InspectionData.from_inspection(host, args)
config = {'mutation_type': 'INSTR_WORD_MOD', 'step': 3222, 'word': 0x0016B213}
fd, p = tempfile.mkstemp(suffix='.json')
os.close(fd)
open(p, 'w').write(json.dumps(config))
env = dict(os.environ)
env.update({
    'A4_MUTATION_CONFIG': p,
    'CONSTRAINT_CONTINUE': '1',
    'A4_COVERAGE_TOUCH': '1',
    'A4_FAMILY_RESIDUE': '1',
    'A4_TRACE_TXN': '1',
})
result = subprocess.run([host] + args, capture_output=True, text=True, env=env)
output = result.stdout + result.stderr
# Grep for x4 and x14 address references (word addrs)
# x4 = 0x3fffc024, x14 = 0x3fffc02e
lines = output.split('\n')
for line in lines:
    if '0x3fffc024' in line or '0x3fffc02e' in line:
        if 'getMemoryTxn' in line:
            print(line)
print('---')
# Also show SKIP THROWs
for line in lines:
    if 'SKIP THROW' in line or 'address mismatch' in line:
        print(line)
print('---')
print('Exit code: %d' % result.returncode)
