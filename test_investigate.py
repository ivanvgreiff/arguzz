import json, os, subprocess, tempfile, sys, re
sys.path.insert(0, '.')
from a4.core.inspection_data import InspectionData
from a4.standalone.mutations import get_instr_word_targets
from a4.standalone.mutations.instr_word_mod_sur import (
    get_targets_at_step, select_surgical_field, generate_field_value,
)
import random

host = './workspace/output/target/release/risc0-host'
args = ['--in1', '5', '--in4', '10']
print('Running inspection...')
data = InspectionData.from_inspection(host, args)

# Reproduce SLTIU x14,x13,1 -> SLTIU x4,x13,1 (rd 14->4)
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
})
result = subprocess.run([host] + args, capture_output=True, text=True, env=env)
output = result.stdout + result.stderr
for m in re.finditer(r'<a4_family_detail>(.*?)</a4_family_detail>', output):
    obj = json.loads(m.group(1))
    if obj.get('family') == 'memory':
        print('MEMORY DETAIL:')
        print(json.dumps(obj, indent=2))
print('Exit code: %d' % result.returncode)
