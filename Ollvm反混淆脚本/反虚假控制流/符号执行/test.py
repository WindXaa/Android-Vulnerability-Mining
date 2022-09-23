import sys
sys.path.append('..')

import os
import nose
import util

test_location = os.path.dirname(os.path.realpath(__file__))

def run_debogus(binary, addr):
    os.system("python3 ./debogus.py -f %s --addr %#x" % (binary, addr))


def test_bogus_control_flow():
    binary_path = os.path.join(test_location, 'samples', 'bin')

    bogus_binary_x86 = os.path.join(binary_path, 'target_x86_bogus')
    run_debogus(bogus_binary_x86, 0x080483E0)
    bogus_binary_x86_recovered = os.path.join(binary_path, 'target_x86_bogus_recovered')
    nose.tools.assert_equal(util.calc_md5(bogus_binary_x86_recovered), "ba56f7e5278a0c0ac32b7f4d2eb378f3")

    bogus_binary_arm = os.path.join(binary_path, 'target_arm_bogus')
    run_debogus(bogus_binary_arm, 0x83B4)
    bogus_binary_arm_recovered = os.path.join(binary_path, 'target_arm_bogus_recovered')
    nose.tools.assert_equal(util.calc_md5(bogus_binary_arm_recovered), "87343c8c6e1e3fec76f9c513d51c0144")


if __name__ == "__main__":
    test_bogus_control_flow()
